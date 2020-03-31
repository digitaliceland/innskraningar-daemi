using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml;
using System.Xml.XPath;

namespace IslyklarSAMLDemo.Helpers
{
    public class IslyklarHelper
    {
        /// <summary>
        /// SSN of SAML Signer(Þjóðskrá)
        /// </summary>
        private static string SignerSSN = "6503760649";
        /// <summary>
        /// Name of issuing CA
        /// </summary>
        private static string IssuerName = "Traustur bunadur";
        /// <summary>
        /// SSN of issuing CA (Auðkenni)
        /// </summary>
        private static string IssuerSSN = "5210002790";

        public static IslyklarReturn VerifyTokenNative(string token, string destination, string destinationSsn, string authId, string ip, string useragent, bool base64 = true)
        {
            IslyklarReturn info = new IslyklarReturn();
            if (string.IsNullOrWhiteSpace(token))
                info.Message = "Token is null or empty";
            try
            {
                string saml = null;
                //Base64 decode the token
                if (base64)
                    saml = Encoding.UTF8.GetString(System.Convert.FromBase64String(token));
                else
                    saml = token;                
                XmlDocument doc = new XmlDocument();
                doc.PreserveWhitespace = true;                
                doc.XmlResolver = null;
                doc.LoadXml(saml);         
                info.SAML = saml;               
                SignedXml signedXml = new SignedXml(doc);
                //Lets begin by getting the Signature element                
                XmlNode signNode = doc.SelectSingleNode("/*[local-name() = 'Response']/*[local-name() = 'Signature']");
                //Then the certificate element               
                XmlNode certNode = doc.SelectSingleNode("/*[local-name() = 'Response']/*[local-name() = 'Signature']/*[local-name() = 'KeyInfo']/*[local-name() = 'X509Data']/*[local-name() = 'X509Certificate']");                 
                //Load signature xml to SignedXML
                signedXml.LoadXml((XmlElement)signNode);
                //Get the certificate to a X509Certificate object                
                X509Certificate2 cert = new X509Certificate2(Encoding.Default.GetBytes(certNode.InnerText));
                info.Signer = cert;
                //This might be needed if using old framework
                //CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                //First we check if the XML signature is valid
                info.SignatureOK = signedXml.CheckSignature(info.Signer, true);
                //Then we check if the certifiate is trusted (chain in appropriate stores)
                info.TrustedCert = cert.Verify();
                //Fetch certifcat attributes from signer certificate and the issuer
                var signerAttributes = GetCertAttributes(cert.Subject);
                var issuerAttributes = GetCertAttributes(cert.Issuer);
                //Check if the issuer is correct (Traustur bunadur with SSN of Auðkenni)
                info.TrustedIssuer = issuerAttributes.Where(i => i.Key == "CN").FirstOrDefault().Value == IssuerName &&
                    issuerAttributes.Where(i => i.Key == "SERIALNUMBER").FirstOrDefault().Value == IssuerSSN;
                //Check if certificate is issued to Þjóðskrá Íslands
                info.TrustedSigner = signerAttributes.Where(i => i.Key == "SERIALNUMBER").FirstOrDefault().Value == SignerSSN;
                if (info.SignatureOK && info.TrustedCert)
                {
                    info.Destination = doc.DocumentElement.Attributes["Destination"].Value.ToLower();
                    //Check if this SAML is intended for this destination
                    info.DestinationOK = destination.ToLower().StartsWith(info.Destination);                    
                    if (info.TrustedSigner && info.TrustedIssuer)
                    {                        
                        DateTime nowTime = DateTime.UtcNow;
                        //Get the conditions from the assertion element
                        XmlNode condition = doc.SelectSingleNode("/*[local-name() = 'Response']/*[local-name() = 'Assertion']/*[local-name() = 'Conditions']");

                        DateTime fromTime = DateTime.Parse(condition.Attributes["NotBefore"].Value);
                        DateTime toTime = DateTime.Parse(condition.Attributes["NotOnOrAfter"].Value);
                        //Is the SAML valid now
                        info.ValidityOK = (nowTime > fromTime && toTime > nowTime);
                        info.ValidFrom = fromTime;
                        info.ValidTo = toTime;
                        //Get the issuer element from the assertion element
                        XmlNode issuer = doc.SelectSingleNode("/*[local-name() = 'Response']/*[local-name() = 'Assertion']/*[local-name() = 'Issuer']");
                        info.Issuer = issuer.InnerText;
                        //Get the attribute list from the attibute statement inside the assertion element
                        XmlNodeList attrList = doc.SelectSingleNode("/*[local-name() = 'Response']/*[local-name() = 'Assertion']/*[local-name() = 'AttributeStatement']").ChildNodes;
                        if (attrList.Count > 0)
                        {
                            //Loop through the attribute list to fetch attributes
                            foreach (XmlNode attr in attrList)
                            {
                                info.Attributes.Add(new IslyklarReturn.IslyklarAttribute
                                {
                                    Format = attr.Attributes["NameFormat"].Value,
                                    Name = attr.Attributes["Name"].Value,
                                    FriendlyName = attr.Attributes["FriendlyName"].Value,
                                    Value = attr.FirstChild.InnerText
                                });
                            }
                            info.Authentication = info.Attributes.Where(i => i.Name == "Authentication").FirstOrDefault().Value;
                            info.AuthID = (info.Attributes.Where(i => i.Name == "AuthID").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            //Check if our auth ID matches the one provided in the SAML
                            if (!string.IsNullOrWhiteSpace(authId))
                                info.AuthIDOK = authId.Equals(info.AuthID);
                            else
                                info.AuthIDOK = true;
                            info.KeyAuthentication = (info.Attributes.Where(i => i.Name == "KeyAuthentication").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            info.DestinationSSN = info.Attributes.Where(i => i.Name == "DestinationSSN").FirstOrDefault().Value;
                            //Check if destination SSN mathces our our SSN
                            info.DestinationOK = info.DestinationOK && destinationSsn.Equals(info.DestinationSSN);                            
                            info.UserAgent = info.Attributes.Where(i => i.Name == "UserAgent").FirstOrDefault().Value;
                            //Check if the users broweser matches the one used for authentication
                            if (!string.IsNullOrWhiteSpace(useragent))
                                info.UserAgentOK = useragent.Equals(info.UserAgent);
                            else
                                info.UserAgentOK = true;
                            info.UserIP = info.Attributes.Where(i => i.Name == "IPAddress").FirstOrDefault().Value;
                            //Check if the users IP matches the one seen at authentication (note this is not always a reliable check i.e. when site is hosted on internal network)
                            if (!string.IsNullOrWhiteSpace(ip))
                                info.UserIPOK = ip.Equals(info.UserIP);
                            else
                                info.UserIPOK = true;
                            info.UserName = info.Attributes.Where(i => i.Name == "Name").FirstOrDefault().Value;
                            info.UserSSN = info.Attributes.Where(i => i.Name == "UserSSN").FirstOrDefault().Value;
                            info.OnbehalfRight = (info.Attributes.Where(i => i.Name == "BehalfRight").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            info.OnBehalfName = (info.Attributes.Where(i => i.Name == "OnBehalfName").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            info.OnbehalfSSN = (info.Attributes.Where(i => i.Name == "OnBehalfUserSSN").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            info.OnbehalfValue = (info.Attributes.Where(i => i.Name == "BehalfValue").FirstOrDefault() ?? new IslyklarReturn.IslyklarAttribute()).Value;
                            if(info.Attributes.Where(i => i.Name == "BehalfValidity").FirstOrDefault() != null)
                                info.OnbehalfValidity = DateTime.Parse(info.Attributes.Where(i => i.Name == "BehalfValidity").FirstOrDefault().Value);
                        }
                    }                    
                }
            }
            catch (Exception ex)
            {
                //There has been an error
                info.Message = ex.Message + ex.StackTrace;
            }
            return info;
        }
        
        /// <summary>
        /// Get certificate attributes from certificate subject
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public static List<KeyValuePair<string, string>> GetCertAttributes(string subject)
        {
            List<KeyValuePair<string, string>> attributes = null;
            if (!string.IsNullOrWhiteSpace(subject) && subject.Contains(','))
            {
                try
                {
                    attributes = new List<KeyValuePair<string, string>>();
                    string[] subjectArray = subject.Split(new char[] { ',', '+' });
                    foreach (var sub in subjectArray)
                    {
                        string[] subsplit = sub.Split('=');
                        if (subsplit.Length == 2)
                            attributes.Add(new KeyValuePair<string, string>(subsplit[0].Trim(), subsplit[1].Trim()));
                    }
                }
                catch (Exception ex)
                {
                    //Problem...
                }        
            }            
            return attributes;
        }
    }
}