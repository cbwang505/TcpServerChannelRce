﻿using System;
using System.IO;
using System.Text;

namespace ChannelRce
{
    public class TcpMessageWriter
    {
        private readonly BinaryWriter writer;

        public TcpMessageWriter(BinaryWriter writer)
        {
            this.writer = writer;
        }

        public void WritePreamble(OperationType operationType, int contentLength)
        {
            writer.Write((uint)0x54454E2E); // ProtocolId
            writer.Write((byte)1); // MajorVersion
            writer.Write((byte)0); // MinorVersion
            writer.Write((ushort)operationType); // OperationType
            writer.Write((ushort)ContentDistribution.NotChunked); // ContentDistribution
            writer.Write(contentLength); // Length
        }

        public void WriteEndHeader()
        {
            writer.Write((ushort)HeaderToken.EndHeaders);
        }

        public void WriteCustomHeader(string headerName, string headerValue)
        {
            writer.Write((ushort)HeaderToken.Custom);
            this.WriteCountedString(headerName);
            this.WriteCountedString(headerValue);
        }

        public void WriteStatusCodeHeader(bool isError)
        {
            writer.Write((ushort)HeaderToken.StatusCode);
            writer.Write((ushort)(isError ? 1 : 0));
        }

        public void WriteStatusPhraseHeader(string statusPhrase)
        {
            writer.Write((ushort)HeaderToken.StatusPhrase);
            WriteCountedString(statusPhrase);
        }

        public void WriteRequestUriHeader(Uri requestUri)
        {
            writer.Write((ushort)HeaderToken.RequestUri);
            writer.Write((byte)HeaderDataFormat.CountedString);
            WriteCountedString(requestUri.ToString());
        }

        public void WriteCloseConnectionHeader()
        {
            writer.Write((ushort)HeaderToken.CloseConnection);
            writer.Write((byte)HeaderDataFormat.Void);
        }

        public void WriteContentTypeHeader(string contentType)
        {
            writer.Write((ushort)HeaderToken.ContentType);
            writer.Write((byte)HeaderDataFormat.CountedString);
            WriteCountedString(contentType);
        }

        public void WriteCountedString(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            writer.Write((byte)StringEncoding.Utf8);
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
    }
    public enum OperationType : ushort
    {
        Request,
        OneWayRequest,
        Reply,
    }
    public enum ContentDistribution : ushort
    {
        NotChunked,
        Chunked,
    }
    public enum HeaderToken : ushort
    {
        EndHeaders,
        Custom,
        StatusCode,
        StatusPhrase,
        RequestUri,
        CloseConnection,
        ContentType,
    }
    public enum HeaderDataFormat : byte
    {
        Void,
        CountedString,
        Byte,
        Uint16,
        Int32,
    }
    public enum StringEncoding : byte
    {
        Unicode,
        Utf8,
    }
    public enum TcpStatusCode : byte
    {
        Success,
        Error,
    }
}