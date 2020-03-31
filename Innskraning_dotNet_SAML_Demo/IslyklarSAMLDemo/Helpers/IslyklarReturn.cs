using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace IslyklarSAMLDemo.Helpers
{
    public class IslyklarReturn
    {
        public IslyklarReturn()
        {
            Attributes = new List<IslyklarAttribute>();
        }
        /// <summary>
        /// Attributes in SAML
        /// </summary>
        public List<IslyklarAttribute> Attributes { get; set; }
        /// <summary>
        /// The users authenticaton
        /// </summary>
        public string Authentication { get; set; }
        /// <summary>
        /// AuthID if present
        /// </summary>
        public string AuthID { get; set; }
        /// <summary>
        /// Does the supplied AuthID match the one in SAML
        /// </summary>
        public bool AuthIDOK { get; set; }
        /// <summary>
        /// The destination for SAML
        /// </summary>
        public string Destination { get; set; }
        /// <summary>
        /// Does the destination match the one in SAML
        /// </summary>
        public bool DestinationOK { get; set; }
        /// <summary>
        /// The destination SSN
        /// </summary>
        public string DestinationSSN { get; set; }
        /// <summary>
        /// ID of SAML
        /// </summary>
        public string ID { get; set; }
        /// <summary>
        /// Issuer of SAML
        /// </summary>
        public string Issuer { get; set; }
        /// <summary>
        /// Authentication of users Icekey (bank, mail etc)
        /// </summary>
        public string KeyAuthentication { get; set; }
        /// <summary>
        /// Message for validation
        /// </summary>
        public string Message { get; set; }
        /// <summary>
        /// Name of onbehalf entitiy if present
        /// </summary>
        public string OnBehalfName { get; set; }
        /// <summary>
        /// Onbehalf right if present
        /// </summary>
        public string OnbehalfRight { get; set; }
        /// <summary>
        /// SSN of onbehalf entitiy if present
        /// </summary>
        public string OnbehalfSSN { get; set; }
        /// <summary>
        /// Validity of behalf right if present
        /// </summary>
        public DateTime? OnbehalfValidity { get; set; }
        /// <summary>
        /// Onbehalf value if present
        /// </summary>
        public string OnbehalfValue { get; set; }
        /// <summary>
        /// The decoded SAML
        /// </summary>
        public string SAML { get; set; }
        /// <summary>
        /// The SAML signer certificate
        /// </summary>
        public X509Certificate2 Signer { get; set; }
        /// <summary>
        /// Is the SAML signature OK (untampered)
        /// </summary>
        public bool SignatureOK { get; set; }         
        /// <summary>
        /// Is the SAML signing certificate trusted
        /// </summary>
        public bool TrustedCert { get; set; }
        /// <summary>
        /// Is the SAML signer issuer trusted
        /// </summary>
        public bool TrustedIssuer { get; set; }
        /// <summary>
        /// Is the SAML signer trusted
        /// </summary>
        public bool TrustedSigner { get; set; }
        /// <summary>
        /// The user agent string of user
        /// </summary>
        public string UserAgent { get; set; }
        /// <summary>
        /// Does the user agent match the one in SAML
        /// </summary>
        public bool UserAgentOK { get; set; }
        /// <summary>
        /// The users IP as seen from innskraning.island.is
        /// </summary>
        public string UserIP { get; set; }
        /// <summary>
        /// Does the IP of user match the one in SAML
        /// </summary>
        public bool UserIPOK { get; set; }        
        /// <summary>
        /// Users name
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// Users mobile
        /// </summary>
        public string UserPhone { get; set; }
        /// <summary>
        /// Users SSN
        /// </summary>
        public string UserSSN { get; set; }
        /// <summary>
        /// SAML valid from
        /// </summary>
        public DateTime ValidFrom { get; set; }
        /// <summary>
        /// SAML valid to
        /// </summary>
        public DateTime ValidTo { get; set; }
        /// <summary>
        /// Is SAML validity OK
        /// </summary>
        public bool ValidityOK { get; set; }

        /// <summary>
        /// Is the SAML valid
        /// </summary>
        /// <returns></returns>
        public bool Valid()
        {
            Message = "";
            if (!TrustedCert)
                Message += "Not a valid SAML certificate. ";
            if (!SignatureOK)
                Message += "Invalid SAML signature. ";
            if (!TrustedSigner)
                Message += "Not a trusted SAML signer. ";
            if (!TrustedIssuer)
                Message += "Not a trusted certificate issuer. ";
            if (!ValidityOK)
                Message += "Invalid validity. ";
            if (!AuthIDOK)
                Message += "Invalid auth ID. ";
            if (!UserAgentOK)
                Message += "Invalid user agent. ";
            if (!UserIPOK)
                Message += "Invalid user IP. ";
            if (!DestinationOK)
                Message += "Invalid destination. ";
            return TrustedCert && ValidityOK && SignatureOK && TrustedSigner && TrustedIssuer && 
                AuthIDOK && UserAgentOK && UserIPOK && DestinationOK;
        }

        /// <summary>
        /// Get QAA of users authentication
        /// </summary>
        /// <returns></returns>
        public int Qaa()
        {
            if (string.IsNullOrWhiteSpace(Authentication))
                return 0;
            else
            {
                if (Authentication.Contains("skilríki"))
                    return 4;
                if (Authentication.Contains("Styrktur"))
                    return 3;
                else
                    return 2;
            }
        }

        public class IslyklarAttribute
        {
            public string Format { get; set; }
            public string FriendlyName { get; set; }
            public string Name { get; set; }
            public string Value { get; set; }
        }
    }
}