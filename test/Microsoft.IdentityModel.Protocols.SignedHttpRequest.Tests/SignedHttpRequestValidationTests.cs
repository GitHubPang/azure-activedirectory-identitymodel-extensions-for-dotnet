﻿//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public class SignedHttpRequestValidationTests
    {
        private readonly static string _encodedTokenHelper = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJwb3AifQ.eyJhdCI6eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIxNjE2MDA2MDE3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNitGckZrdC9UQnlRL0w1ZDdvcis5UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkreXlTdmluQXUzeVFEUW91MkdhNDJNTC8rSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDLzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dS9tSWR5d3lHZmdpVDN0dzBGc1d2a2kvS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZK0ovZWxxK0hnSi9kWks2Zzd2TU52WHoyL3ZUK1N5a0lrendpRDllU0k5VVdmc2p3PT0iLCJlIjoiQVFBQiIsImFsZyI6IlJTMjU2Iiwia2lkIjoiUnNhU2VjdXJpdHlLZXlfMjA0OCJ9fX0sIm0iOiJHRVQiLCJ1Ijoid3d3LmNvbnRvc28uY29tIiwicCI6Ii9wYXRoMSIsInEiOiJbW1wiYlwiLFwiYVwiLFwiY1wiXSxcInU0TGdrR1VXaFA5TXNLckVqQTRkaXpJbGxEWGx1RGt1NlpxQ2V5dVItSllcIl0iLCJoIjoiW1tcImNvbnRlbnQtdHlwZVwiLFwiZXRhZ1wiXSxcIlA2ejVYTjR0VHpIa2Z3ZTNYTzFZdlZVSXVyU3VodmhfVUcxME5fai1hR3NcIl0iLCJiIjoiWkstTzJnekhqcHNDR3BlZDZzVUwyRU0yMFo5VC11RjA3TENHTUE4OFVGdyIsIm5vbmNlIjoiODFkYTQ5MGY0NmMzNDk0ZWJhOGM2ZTI1YTQ1YTRkMGYiLCJ0cyI6MTU2OTk0NDc2OSwiZXhwIjoxNTY5OTczNTc4LjAsImlhdCI6MTU2OTk2OTk3OCwibmJmIjoxNTY5OTY5OTc4fQ.OiLM-S_Da8gwKw3dxXI-4TMyH9JZuKCdJnr_1xyFg1UbhKe2kuWA9J6nBtuAWHXUxHpvwwHNYcEjB6eNMJFEHnAVwEvaMgJCmI0dG6xof201riSKqflFJxh2fq7z2clReWpLLmP0o1S1LGSx74g5cubl90ivQ7MoYPeyIMoSTfGwsTGXKAnf4MnCIt3Ykp0KbTj6WHnS1LmtSCTBGXslV7jD28ikjF3w5Xk2Nv6WmUJAYNhGC3fiUnzqt3buiyynhF4sXbYxKDLYPeUWH-oZVEFuaGC2nnTA_5-aS0yHPmcj-CDRanHAZA9Y-UFMyFm9oO-QffHc-ZL8mcIfx-Kmfg";
        
        [Theory, MemberData(nameof(ValidateTsClaimTheoryData))]
        public void ValidateTsClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTsClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateTsClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateTsClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Ts, (long)(DateTime.UtcNow - EpochTime.UnixEpoch).TotalSeconds) ),
                        TestId = "ValidTs",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Ts, (long)(DateTime.UtcNow.AddHours(1) - EpochTime.UnixEpoch).TotalSeconds) ),
                        TestId = "ValidTs2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Ts, (long)(DateTime.UtcNow.AddMinutes(-6) - EpochTime.UnixEpoch).TotalSeconds) ),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23010"),
                        TestId = "Expired",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Ts, (DateTime.UtcNow- EpochTime.UnixEpoch).TotalSeconds.ToString())),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23003"),
                        TestId = "InvalidNotLong",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Ts, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateMClaimTheoryData))]
        public void ValidateMClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateMClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateMClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateMClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, "GET")),
                        TestId = "ValidM1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, "get")),
                        TestId = "ValidM2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = " GET  ",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, "  gEt     ")),
                        TestId = "ValidM3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "POST",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, "GET")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidMClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "EmptyExpectedMethod",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = null,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullExpectedMethod",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.M, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidMClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateUClaimTheoryData))]
        public void ValidateUClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateUClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateUClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateUClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso.com")),
                        TestId = "ValidU1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.CONTOSO.com")),
                        TestId = "ValidU2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso.com:443")),
                        TestId = "ValidU3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com:443"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso.com")),
                        TestId = "ValidU4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com:443"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso.com:443")),
                        TestId = "ValidU5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso2.com")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23012"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("/path1", UriKind.Relative),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, "www.contoso.com")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23001"),
                        TestId = "InvalidRelativeUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.U, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidatePClaimTheoryData))]
        public void ValidatePClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidatePClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidatePClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidatePClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1")),
                        TestId = "ValidP1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1/")),
                        TestId = "ValidP2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "path1")),
                        TestId = "ValidP3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "path1/")),
                        TestId = "ValidP4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("/path1", UriKind.Relative),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1")),
                        TestId = "ValidP5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/pa th1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/pa%20th1")),
                        TestId = "ValidP6",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1/more/andmore")),
                        TestId = "ValidP8",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1/more/andmore/")),
                        TestId = "ValidP9",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore/"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path1/more/andmore/")),
                        TestId = "ValidP10",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, "/path2")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.P, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateHClaimTheoryData))]
        public void ValidateHClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateHClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateHClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateHClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    // the specification has incorrect hash value ("bZA981YJBrPlIzOvplbu3e7ueREXXr38vSkxIBYOaxI")
                    // because authors used "\r\n" as a separator instead of "\n" as stated in the spec.
                    // "P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs" is the value if "\n" is used as a separator.
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "content-type" , new List<string> { "application/json" } },
                            { "etag" , new List<string> { "742-3u8f34-3r2nvv3" } },
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"content-type\", \"etag\"],\"P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs\"]"))),
                        TestId = "ValidHSpecTest",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        TestId = "ValidH1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidH2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { SignedHttpRequestConstants.AuthorizationHeader , new List<string> { "exyz...." } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        TestId = "ValidH3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { SignedHttpRequestConstants.AuthorizationHeader.ToLower() , new List<string> { "exyz...." } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        TestId = "ValidH4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } }

                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\",\"headername2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1\nheadername2: headerValue2")}\"]"))),
                        TestId = "ValidH5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } },
                            { "headerName3" , new List<string> { "headerValue3" } },

                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\",\"headername2\",\"headername3\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1\nheadername2: headerValue2\nheadername3: headerValue3")}\"]"))),
                        TestId = "ValidH6",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1", "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidHRepeated1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HEADERNAME1" , new List<string> { "headerValue1" } },
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidHRepeated2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1", "headerValue2" } },
                            { "headerName2" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername2: headerValue2")}\"]"))),
                        TestId = "ValidHRepeated3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HeaderNAME1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername2: headerValue2")}\"]"))),
                        TestId = "ValidHRepeated4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HEADERNAME1" , new List<string> { "headerValue1" } },
                            { "HeaderNAME1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername2: headerValue2")}\"]"))),
                        TestId = "ValidHRepeated5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HEADERNAME1" , new List<string> { "headerValue1" } },
                            { "HeaderNAME1" , new List<string> { "headerValue1" } },
                            { "headerName3" , new List<string> { "headerValue3" } },
                            { "headerName2" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername2\",\"headername3\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername2: headerValue2\nheadername3: headerValue3")}\"]"))),
                        TestId = "ValidHRepeated6",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HEADERNAME1" , new List<string> { "headerValue1" } },
                            { "HeaderNAME1" , new List<string> { "headerValue1" } },
                            { "headerName3" , new List<string> { "headerValue3" } },
                            { "headerName2" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername3\",\"headername2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername3: headerValue3\nheadername2: headerValue2")}\"]"))),
                        TestId = "ValidHRepeated7",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } }

                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        TestId = "ValidAcceptUnsignedHeaders",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } }

                        },
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateH = true,
                            AcceptUnsignedHeaders = false,
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23026"),
                        TestId = "InvalidDontAcceptUnsignedHeaders",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue2" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23011"),
                        TestId = "InvalidMismatchValue",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName2" , new List<string> { "headerValue1" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[[\"headername1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23025", typeof(SignedHttpRequestInvalidHClaimException)),
                        TestId = "InvalidHeaderNameMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName2" , new List<string> { "headerValue1" } }
                        },
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, JArray.Parse($"[\"headername1\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23024", null, true),
                        TestId = "InvalidNumberOfArguments",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = null,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullHeaders",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, "notAnArray")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23003"),
                        TestId = "InvalidClaimType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.H, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateQClaimTheoryData))]
        public void ValidateQClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateQClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateQClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateQClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestUri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"b\", \"a\", \"c\"],\"u4LgkGUWhP9MsKrEjA4dizIllDXluDku6ZqCeyuR-JY\"]"))),
                        TestId = "ValidQSpecTest",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        TestId = "ValidQ1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam2=value2"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\",\"queryParam2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1&queryParam2=value2")}\"]"))),
                        TestId = "ValidQ2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam2=value2&queryParam1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\",\"queryParam2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1&queryParam2=value2")}\"]"))),
                        TestId = "ValidQ3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("/path1?queryParam1=value1", UriKind.Relative),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        TestId = "ValidQ4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidQ5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?query Param1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"query%20Param1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("query%20Param1=value1")}\"]"))),
                        TestId = "ValidQ6",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=val ue1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=val%20ue1")}\"]"))),
                        TestId = "ValidQ7",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&QUERYParam1=value2"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\",\"QUERYParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1&QUERYParam1=value2")}\"]"))),
                        TestId = "ValidQ8",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam2=value2&queryParam1=value1&queryParam2=value3"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        TestId = "ValidQRepeated1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam2=value2&queryParam2=value22&queryParam1=value1&queryParam2=value3"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        TestId = "ValidQRepeated2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam1=value2"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidQRepeated3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam1=value2&queryParam1=value3"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")}\"]"))),
                        TestId = "ValidQRepeated4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam2=value2"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        TestId = "ValidAcceptUnsignedQueryParams",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam2=value2"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23029"),
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateH = true,
                            AcceptUnsignedQueryParameters = false,
                        },
                        TestId = "InvalidDontAcceptUnsignedQueryParams",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[\"queryParam1\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23024", null, true),
                        TestId = "InvalidNumberOfArguments",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam2\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23025", typeof(SignedHttpRequestInvalidQClaimException)),
                        TestId = "InvalidQueryParamNameMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, JArray.Parse($"[[\"queryParam1\"],\"{SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("queryParam1=value2")}\"]"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23011"),
                        TestId = "InvalidValueMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, null)),
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.Q,  "notAnArray")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidQClaimException), "IDX23003"),
                        TestId = "InvalidClaimType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateBClaimTheoryData))]
        public void ValidateBClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateBClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                handler.ValidateBClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationContext);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateBClaimTheoryData
        {
            get
            {
                var signedHttpRequestWithCustomB = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.B, SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("abcd")));
                var signedHttpRequestWithEmptyB = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.B, SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash("")));
                var signedHttpRequestWithNullB = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.B, null));
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestBody = Encoding.UTF8.GetBytes("abcd"),
                        SignedHttpRequestToken = signedHttpRequestWithCustomB,
                        TestId = "ValidB1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestBody = Encoding.UTF8.GetBytes("aaaa"),
                        SignedHttpRequestToken = signedHttpRequestWithCustomB,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidBClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestBody = null,
                        SignedHttpRequestToken = signedHttpRequestWithEmptyB,
                        TestId = "NullBytesValid",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequestWithNullB,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidBClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateSignedHttpRequestCallsTheoryData))]
        public async Task ValidateSignedHttpRequestCalls(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateSignedHttpRequestCalls", theoryData);
            var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();

            var handler = new SignedHttpRequestHandlerPublic();
             var signedHttpRequest = await handler.ValidateSignedHttpRequestPublicAsync(theoryData.SignedHttpRequestToken, null, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

            var methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateTsClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateTs)
                context.AddDiff($"ValidationParameters.ValidateTs={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateTs}, ValidateTsClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateMClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateM)
                context.AddDiff($"ValidationParameters.ValidateM={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateM}, ValidateMClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateUClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateU)
                context.AddDiff($"ValidationParameters.ValidateU={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateU}, ValidateUClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidatePClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateP)
                context.AddDiff($"ValidationParameters.ValidateP={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateP}, ValidatePClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateQClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateQ)
                context.AddDiff($"ValidationParameters.ValidateQ={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateQ}, ValidateQClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateHClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateH)
                context.AddDiff($"ValidationParameters.ValidateH={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateH}, ValidateHClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateBClaimCall"];
            if (methodCalledStatus != signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateB)
                context.AddDiff($"ValidationParameters.ValidateB={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateB}, ValidateBClaim method call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_AdditionalClaimValidatorCall"];
            if (methodCalledStatus != (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AdditionalClaimValidatorAsync != null))
                context.AddDiff($"ValidationParameters.AdditionalClaimValidatorAsync={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AdditionalClaimValidatorAsync != null}, AdditionalClaimValidator call status: {methodCalledStatus}.");

            methodCalledStatus = (bool)signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ReplayValidatorCall"];
            if (methodCalledStatus != (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignedHttpRequestReplayValidatorAsync != null))
                context.AddDiff($"ValidationParameters.SignedHttpRequestReplayValidatorAsync={signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignedHttpRequestReplayValidatorAsync != null}, ReplayValidator call status: {methodCalledStatus}.");

            if (signedHttpRequest.SigningKey == null)
                context.AddDiff("signedHttpRequest.SigningKey == null");

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateSignedHttpRequestCallsTheoryData
        {
            get
            {
                var signedHttpRequestToken = SignedHttpRequestTestUtils.CreateDefaultSignedHttpRequestToken(SignedHttpRequestTestUtils.DefaultSignedHttpRequestPayload.ToString());
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestToken = signedHttpRequestToken,
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateTs = true,
                            ValidateM = true,
                            ValidateP = true,
                            ValidateQ = true,
                            ValidateU = true,
                            ValidateH = true,
                            ValidateB = true,
                            AdditionalClaimValidatorAsync = async (SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_AdditionalClaimValidatorCall"] = true;
                                await Task.FromResult<object>(null);
                            },
                            SignedHttpRequestReplayValidatorAsync = async (string nonce, SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ReplayValidatorCall"] = true;
                                await Task.FromResult<object>(null);
                            }
                        },
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockValidateSignedHttpRequestSignatureAsync", null },
                                {"onlyTrack_ValidateTsClaimCall", false },
                                {"onlyTrack_ValidateMClaimCall", false },
                                {"onlyTrack_ValidateUClaimCall", false },
                                {"onlyTrack_ValidatePClaimCall", false },
                                {"onlyTrack_ValidateQClaimCall", false },
                                {"onlyTrack_ValidateHClaimCall", false },
                                {"onlyTrack_ValidateBClaimCall", false },
                                {"onlyTrack_AdditionalClaimValidatorCall", false },
                                {"onlyTrack_ReplayValidatorCall", false },
                            }
                        },
                        TestId = "ValidAllCalls",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestToken = signedHttpRequestToken,
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateTs = false,
                            ValidateM = false,
                            ValidateP = false,
                            ValidateQ = false,
                            ValidateU = false,
                            ValidateH = false,
                            ValidateB = false,
                            AdditionalClaimValidatorAsync = null,
                            SignedHttpRequestReplayValidatorAsync = null,
                        },
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockValidateSignedHttpRequestSignatureAsync", null },
                                {"onlyTrack_ValidateTsClaimCall", false },
                                {"onlyTrack_ValidateMClaimCall", false },
                                {"onlyTrack_ValidateUClaimCall", false },
                                {"onlyTrack_ValidatePClaimCall", false },
                                {"onlyTrack_ValidateQClaimCall", false },
                                {"onlyTrack_ValidateHClaimCall", false },
                                {"onlyTrack_ValidateBClaimCall", false },
                                {"onlyTrack_AdditionalClaimValidatorCall", false },
                                {"onlyTrack_ReplayValidatorCall", false },
                            }
                        },
                        TestId = "ValidNoCalls",
                    },

                };
            }
        }

        [Theory, MemberData(nameof(ValidateSignedHttpRequestSignatureTheoryData))]
        public async Task ValidateSignedHttpRequestSignature(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateSignedHttpRequestSignature", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var signingKey = await handler.ValidateSignedHttpRequestSignaturePublicAsync(theoryData.SignedHttpRequestToken, theoryData.PopKeys, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);
                IdentityComparer.AreSecurityKeysEqual(signingKey, theoryData.ExpectedPopKey, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateSignedHttpRequestSignatureTheoryData
        {
            get
            {
                var signedHttpRequest = SignedHttpRequestTestUtils.CreateDefaultSignedHttpRequestToken(SignedHttpRequestTestUtils.DefaultSignedHttpRequestPayload.ToString(Formatting.None));
                var validPopKey = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
                var invalidPopKey = KeyingMaterial.RsaSecurityKey1;
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        PopKeys = new List<SecurityKey>() {  validPopKey },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = null,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23030"),
                        TestId = "InvalidNullPopKey",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>(),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23030"),
                        TestId = "InvalidEmptyPopKeys",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>() { invalidPopKey },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23009"),
                        TestId = "InvalidPopKeySignatureValidationFails",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>() {  validPopKey },
                        ExpectedPopKey = validPopKey,
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            SignedHttpRequestSignatureValidatorAsync = (IEnumerable<SecurityKey> popKeys, SecurityToken signedHttpRequestToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                throw new NotImplementedException();
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(NotImplementedException)),
                        TestId = "InvalidDelegateThrows",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>() {  validPopKey },
                        ExpectedPopKey = validPopKey,
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            SignedHttpRequestSignatureValidatorAsync = async (IEnumerable<SecurityKey> popKeys, SecurityToken signedHttpRequestToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                return await Task.FromResult(popKeys.First());
                            }
                        },
                        TestId = "ValidDelegate",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>() {  validPopKey },
                        ExpectedPopKey = validPopKey,
                        TestId = "ValidTest",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        PopKeys = new List<SecurityKey>() {  invalidPopKey, validPopKey },
                        ExpectedPopKey = validPopKey,
                        TestId = "ValidTestTwoKeys",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateSignedHttpRequestTheoryData))]
        public async Task ValidateSignedHttpRequest(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateSignedHttpRequest", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();

                if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("makeSignedHttpRequestValidationContextNull"))
                    signedHttpRequestValidationContext = null;

                var result = await handler.ValidateSignedHttpRequestAsync(signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                if (result.Exception != null)
                    throw result.Exception;

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateSignedHttpRequestTheoryData
        {
            get
            {
                var encodedAccessToken = SignedHttpRequestTestUtils.CreateAt(SignedHttpRequestTestUtils.DefaultCnfJwk, false);
                var encodedEncryptedAccessToken = SignedHttpRequestTestUtils.CreateAt(SignedHttpRequestTestUtils.DefaultCnfJwk, true);

                var signedHttpRequest = SignedHttpRequestTestUtils.CreateDefaultSignedHttpRequestToken(SignedHttpRequestTestUtils.DefaultSignedHttpRequestPayload.ToString(Formatting.None));
                var signedHttpRequestWithEncryptedAt = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.At, encodedEncryptedAccessToken));
                var signedHttpRequestWithNullAt = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.At, null));
                var signedHttpRequestWithEmptyAt = SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(new JProperty(SignedHttpRequestClaimTypes.At, string.Empty));

                var validationResult = new JsonWebTokenHandler().ValidateToken(encodedAccessToken, SignedHttpRequestTestUtils.DefaultTokenValidationParameters);
                var resultingClaimsIdentity = validationResult.ClaimsIdentity;
                var validatedToken = validationResult.SecurityToken;

                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"makeSignedHttpRequestValidationContextNull", null },
                            }
                        },
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidNullSignedHttpRequestValidationContext",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14100"),
                        TestId = "InvalidToken",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequestWithNullAt,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23003"),
                        TestId = "InvalidNoAccessToken",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequestWithEmptyAt,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23003"),
                        TestId = "InvalidEmptyAcccessToken",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockValidateAccessTokenAsync_returnInvalidResult", null },
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23013", typeof(SecurityTokenValidationException)),
                        TestId = "InvalidAccessTokenValidationFailed",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockResolvePopKeyAsync_returnNullKey", null },
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23030"),
                        TestId = "InvalidResolvedPopKeyIsNull",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequestWithEncryptedAt, 
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateB = false,
                            ValidateH = false,
                            ValidateM = false,
                            ValidateP = false,
                            ValidateQ = false,
                            ValidateTs = false,
                            ValidateU = false,
                        },
                        ExpectedSignedHttpRequestValidationResult = new SignedHttpRequestValidationResult()
                        {
                            AccessToken = encodedEncryptedAccessToken,
                            SignedHttpRequest = signedHttpRequestWithEncryptedAt.EncodedToken,
                            ValidatedSignedHttpRequest = signedHttpRequestWithEncryptedAt,
                            SecurityToken = validatedToken,
                            ClaimsIdentity = resultingClaimsIdentity
                        },
                        TestId = "ValidEncryptedAcccessToken",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = signedHttpRequest,
                        SignedHttpRequestValidationParameters = new SignedHttpRequestValidationParameters()
                        {
                            ValidateB = false,
                            ValidateH = false,
                            ValidateM = false,
                            ValidateP = false,
                            ValidateQ = false,
                            ValidateTs = false,
                            ValidateU = false,
                        },
                        ExpectedSignedHttpRequestValidationResult = new SignedHttpRequestValidationResult()
                        {
                            AccessToken = encodedAccessToken,
                            SignedHttpRequest = signedHttpRequest.EncodedToken,
                            ValidatedSignedHttpRequest = signedHttpRequest,
                            SecurityToken = validatedToken,
                            ClaimsIdentity = resultingClaimsIdentity
                        },
                        TestId = "ValidTest",
                    }
                };
            }
        }
    }

    public class ValidateSignedHttpRequestTheoryData : TheoryDataBase
    {
        public SignedHttpRequestValidationContext BuildSignedHttpRequestValidationContext()
        {
            var httpRequestData = new HttpRequestData()
            {
                Body = HttpRequestBody,
                Uri = HttpRequestUri,
                Method = HttpRequestMethod,
                Headers = HttpRequestHeaders
            };

            var tokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters;

            // add testId for debugging purposes
            var callContext = CallContext;
            if (callContext.PropertyBag == null)
                callContext.PropertyBag = new Dictionary<string, object>() { { "testId", TestId } };
            else
                callContext.PropertyBag.Add("testId", TestId);

            // set SignedHttpRequestToken if set and if JsonWebToken, otherwise set "dummy" value
            return new SignedHttpRequestValidationContext(SignedHttpRequestToken is JsonWebToken jwt ? jwt.EncodedToken : "dummy", httpRequestData, tokenValidationParameters, SignedHttpRequestValidationParameters, callContext);
        }

        public CallContext CallContext { get; set; } = CallContext.Default;

        public SignedHttpRequestValidationResult ExpectedSignedHttpRequestValidationResult { get; set; }

        public Uri HttpRequestUri { get; set; }

        public string HttpRequestMethod { get; set; }

        public IDictionary<string, IEnumerable<string>> HttpRequestHeaders { get; set; }

        public byte[] HttpRequestBody { get; set; }

        public SignedHttpRequestValidationParameters SignedHttpRequestValidationParameters { get; set; } = new SignedHttpRequestValidationParameters()
        {
            ValidateB = true,
            ValidateH = true,
            ValidateM = true,
            ValidateP = true,
            ValidateQ = true,
            ValidateTs = true,
            ValidateU = true
        };

        public IEnumerable<SecurityKey> PopKeys { get; set; }

        public SecurityKey ExpectedPopKey { get; set; }

        internal SecurityToken SignedHttpRequestToken { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant