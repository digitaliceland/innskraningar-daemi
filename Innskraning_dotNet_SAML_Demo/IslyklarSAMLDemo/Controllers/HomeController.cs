using IslyklarSAMLDemo.Helpers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace IslyklarSAMLDemo.Controllers
{
    public class HomeController : Controller
    {
        //Minimum authentication level (2 = Íslykill, 3 = Styrktur Íslykill, 4 = Rafræn skilríki)
        private string qaa = ConfigurationManager.AppSettings.Get("Qaa") ?? "2";
        private string DestinationSSN = ConfigurationManager.AppSettings.Get("DestinationSSN") ?? "6503760649";
        //The login path to innskraning.island.is
        private string LoginURL = ConfigurationManager.AppSettings.Get("LoginURL") ?? "https://profun.island.is/islyklar/login.aspx?id=test.island.is";
        //Use authid (added int or GUID/UUID to SAML) as an extra layer of security
        private bool UseAuthId = (ConfigurationManager.AppSettings.Get("UseAuthID") ?? "false").Equals("true");
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {            
            return View();
        }

        public ActionResult Contact()
        {         
            return View();
        }

        public ActionResult Login()
        {
            ViewBag.loginUrl = LoginURL;
            ViewBag.qaa = qaa;
            if (UseAuthId)
            {
                string authid = Guid.NewGuid().ToString();
                ViewBag.authid = authid;
                Session["authid"] = authid;
            }
            return View();
        }

        public ActionResult Return(string token)
        {
            IslyklarReturn ret = IslyklarHelper.VerifyTokenNative(token, Request.Url.AbsoluteUri, DestinationSSN,(UseAuthId && Session["authid"] != null) ? Session["authid"].ToString() : null, 
                null, Request.UserAgent);
            if(ret.Valid())
            {
                if (ret.Qaa() >= int.Parse(qaa))
                {
                    ViewBag.message = "Hello " + ret.UserName + ", " + ret.UserSSN;
                    List<string> attributes = new List<string>();
                    foreach (var attr in ret.Attributes)
                        attributes.Add(attr.Name + " : " + attr.Value);
                    ViewBag.attributes = attributes;
                    ViewBag.saml = ret.SAML;
                }
                else
                    ViewBag.message = "Invalid QAA level";
            }
            else
                ViewBag.message = ret.Message;
            return View();
        }
    }
}