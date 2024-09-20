using System;
using System.Collections;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Serialization.Formatters;
using System.Threading;

namespace ChannelServer
{
    public class RemoteType : MarshalByRefObject
    {
    }
    public class Program
    {
      
        static void Main(string[] args)
        {



            try
            {
                bool secure = false;
                // int port = 12345;
                int port = 52012;
                string ipc = string.Empty;
                //string ipc = "LocalPipe";
                bool bind_any = false;
                bool showhelp = false;
                TypeFilterLevel typefilter = TypeFilterLevel.Low;
                CustomErrorsModes custom_errors = CustomErrorsModes.Off;
                // string name = "RemotingServer";
                string name = "SecurityCheckEndpoint";
                bool disable_transparent_proxy_fix = false;



                Console.WriteLine("Example .NET Remoting Server");
                Console.WriteLine("Copyright (c) cbwang505");
                Console.WriteLine(".NET Version: {0}", Environment.Version);


                RemotingConfiguration.CustomErrorsMode = custom_errors;

                Console.WriteLine("Enable Transparent Proxy Fix: {0}", disable_transparent_proxy_fix);
                Console.WriteLine("Custom Errors Mode: {0}", custom_errors);
                Console.WriteLine("Type Filter Level: {0}", typefilter);

                Trace.Listeners.Add(new ConsoleTraceListener(true));

                IChannel chan;
                IDictionary properties = new Hashtable();

                BinaryServerFormatterSinkProvider serverSinkProvider = new BinaryServerFormatterSinkProvider();
                // serverSinkProvider.TypeFilterLevel = typefilter;
                serverSinkProvider.TypeFilterLevel = TypeFilterLevel.Full;
                //  serverSinkProvider.TypeFilterLevel = TypeFilterLevel.Low;

                BinaryClientFormatterSinkProvider clientSinkProvider = new BinaryClientFormatterSinkProvider();
                bool usehttp = false;
                if (!string.IsNullOrEmpty(ipc))
                {
                    properties["portName"] = ipc;
                    properties["authorizedGroup"] = "Everyone";





                    chan = new IpcChannel(properties, new BinaryClientFormatterSinkProvider(), serverSinkProvider);
                }
                else if (usehttp)
                {

                    properties["port"] = port;
                    properties["rejectRemoteRequests"] = !bind_any;

                   // properties["bindTo"] = "127.0.0.1";
                    ///deltav

                    properties["secure"] = (object)true;
                    properties["protectionLevel"] = (object)"EncryptAndSign";
                    properties["impersonation"] = (object)"true";
                    foreach (DictionaryEntry property in properties)
                    {
                        Console.WriteLine("properties Bind: {0} :=>{0}", property.Key, property.Value);
                    }
                    // chan = new TcpChannel(properties, new BinaryClientFormatterSinkProvider(), serverSinkProvider);

                    chan = new HttpChannel(properties, clientSinkProvider, serverSinkProvider);

                }
                else
                {
                    Console.WriteLine("Any Bind: {0}", bind_any);
                    properties["port"] = port;
                    properties["rejectRemoteRequests"] = !bind_any;


                    ///deltav

                    properties["secure"] = (object)true;
                    properties["protectionLevel"] = (object)"EncryptAndSign";
                    properties["impersonation"] = (object)"true";
                    foreach (DictionaryEntry property in properties)
                    {
                        Console.WriteLine("properties Bind: {0} :=>{0}", property.Key, property.Value);
                    }
                    // chan = new TcpChannel(properties, new BinaryClientFormatterSinkProvider(), serverSinkProvider);

                     chan = new TcpServerChannel(properties, (IServerChannelSinkProvider)null);
                   //  chan = new TcpServerChannel(properties, (IServerChannelSinkProvider)serverSinkProvider);
                }
                secure = false;
                ChannelServices.RegisterChannel(chan, secure);    //register channel

                RemotingConfiguration.RegisterWellKnownServiceType(
                    typeof(RemoteType),
                    name,
                    WellKnownObjectMode.Singleton);

                bool isipc = chan is IpcChannel;

                //Console.WriteLine("Server Activated at {0}://{1}/{2}", isipc ? "ipc" : "tcp", isipc ? ipc : "HOST:" + port.ToString(), name);

                Console.WriteLine("Server Activated at {0}://{1}/{2}", isipc ? "ipc" : (usehttp ? "http" : "tcp"), isipc ? ipc : "HOST:" + port.ToString(), name);

                /*Assembly fakeasm = typeof(FakeAsm.ClassFake).Assembly;

                Assembly[] asmls = AppDomain.CurrentDomain.GetAssemblies();
                for (int i = 0; i < asmls.Length; i++)
                {
                    if (asmls[i].FullName == fakeasm.FullName)
                    {
                        Console.WriteLine(i);
                        Console.WriteLine(asmls[i].FullName);
                        Type[] tps = asmls[i].GetTypes();
                        for (int j = 0; j < tps.Length; j++)
                        {
                            Console.WriteLine(j);
                            Console.WriteLine(tps[j].FullName);
                        }
                    }
                }*/

                Console.WriteLine("Console.ReadLine()");

                Console.ReadLine();

                Console.WriteLine("Console.Exit()");

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace.ToString());
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
