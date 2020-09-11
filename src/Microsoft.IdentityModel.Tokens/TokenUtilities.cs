//------------------------------------------------------------------------------
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
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// A class which contains useful methods for processing tokens.
    /// </summary>
    internal partial class TokenUtilities
    {

        /// <summary>
        /// A URI that represents the JSON XML data type.
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), if the value was not a string (or an enumeration of strings), the ClaimValue will serialized using the current JSON serializer, a property will be added with the .Net type and the ClaimTypeValue will be set to 'JsonClaimValueType'.</remarks>
        internal const string Json = "JSON";

        /// <summary>
        /// A URI that represents the JSON array XML data type.
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), if the value was not a string (or an enumeration of strings), the ClaimValue will serialized using the current JSON serializer, a property will be added with the .Net type and the ClaimTypeValue will be set to 'JsonClaimValueType'.</remarks>
        internal const string JsonArray = "JSON_ARRAY";

        /// <summary>
        /// A URI that represents the JSON null data type
        /// </summary>
        /// <remarks>When mapping json to .Net Claim(s), we use empty string to represent the claim value and set the ClaimValueType to JsonNull</remarks>
        internal const string JsonNull = "JSON_NULL";

        /// <summary>
        /// Creates a dictionary from a list of Claim's.
        /// </summary>
        /// <param name="claims"> A list of claims.</param>
        /// <returns> A Dictionary representing claims.</returns>
        internal static IDictionary<string, object> CreateDictionaryFromClaims(IEnumerable<Claim> claims)
        {
            var payload = new Dictionary<string, object>();

            if (claims == null)
                return payload;

            foreach (Claim claim in claims)
            {
                if (claim == null)
                    continue;

                string jsonClaimType = claim.Type;
                object jsonClaimValue = claim.ValueType.Equals(ClaimValueTypes.String, StringComparison.Ordinal) ? claim.Value : GetClaimValueUsingValueType(claim);
                object existingValue;

                // If there is an existing value, append to it.
                // What to do if the 'ClaimValueType' is not the same.
                if (payload.TryGetValue(jsonClaimType, out existingValue))
                {
                    IList<object> claimValues = existingValue as IList<object>;
                    if (claimValues == null)
                    {
                        claimValues = new List<object>();
                        claimValues.Add(existingValue);
                        payload[jsonClaimType] = claimValues;
                    }

                    claimValues.Add(jsonClaimValue);
                }
                else
                {
                    payload[jsonClaimType] = jsonClaimValue;
                }
            }

            return payload;
        }

        /// <summary>
        /// Decrypts a Json Web Token.
        /// </summary>
        /// <param name="jwtToken">The Json Web Token</param>
        /// <param name="validationParameters">The validation parameters containing cryptographic material.</param>
        /// <param name="decryptionParameters">The decryption parameters container.</param>
        /// <returns>The decrypted, and if the 'zip' claim is set, decompressed string representation of the token.</returns>
        public static string DecryptJwtToken(
            SecurityToken jwtToken,
            TokenValidationParameters validationParameters,
            JwtTokenDecryptionParameters decryptionParameters)
        {
            bool decryptionSucceeded = false;
            bool algorithmNotSupportedByCryptoProvider = false;
            byte[] decryptedTokenBytes = null;

            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            foreach (SecurityKey key in decryptionParameters.Keys)
            {
                var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
                if (cryptoProviderFactory == null)
                {
                    LogHelper.LogWarning(TokenLogMessages.IDX10607, key);
                    continue;
                }

                if (!cryptoProviderFactory.IsSupportedAlgorithm(decryptionParameters.Enc, key))
                {
                    algorithmNotSupportedByCryptoProvider = true;
                    LogHelper.LogWarning(TokenLogMessages.IDX10611, decryptionParameters.Enc, key);
                    continue;
                }

                try
                {
                    Validators.ValidateAlgorithm(decryptionParameters.Enc, key, jwtToken, validationParameters);
                    decryptedTokenBytes = DecryptToken(cryptoProviderFactory, key, decryptionParameters);
                    decryptionSucceeded = true;
                    break;
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (key != null)
                    keysAttempted.AppendLine(key.ToString());
            }

            if (!decryptionSucceeded && keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10603, keysAttempted, exceptionStrings, decryptionParameters.EncodedToken)));

            if (!decryptionSucceeded && algorithmNotSupportedByCryptoProvider)
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10619, decryptionParameters.Alg, decryptionParameters.Enc)));

            if (!decryptionSucceeded)
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10609, decryptionParameters.EncodedToken)));

            if (string.IsNullOrEmpty(decryptionParameters.Zip))
                return Encoding.UTF8.GetString(decryptedTokenBytes);

            try
            {
                return decryptionParameters.DecryptionFunction(decryptedTokenBytes, decryptionParameters.Zip);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecompressionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10679, decryptionParameters.Zip), ex));
            }
        }

        private static byte[] DecryptToken(CryptoProviderFactory cryptoProviderFactory, SecurityKey key, JwtTokenDecryptionParameters decryptionParameters)
        {
            using (AuthenticatedEncryptionProvider decryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(key, decryptionParameters.Enc))
            {
                if (decryptionProvider == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10610, key, decryptionParameters.Enc)));

                return decryptionProvider.Decrypt(
                    Base64UrlEncoder.DecodeBytes(decryptionParameters.Ciphertext),
                    Encoding.ASCII.GetBytes(decryptionParameters.EncodedHeader),
                    Base64UrlEncoder.DecodeBytes(decryptionParameters.InitializationVector),
                    Base64UrlEncoder.DecodeBytes(decryptionParameters.AuthenticationTag));
            }
        }

        internal static object GetClaimValueUsingValueType(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.String)
                return claim.Value;

            if (claim.ValueType == ClaimValueTypes.Boolean && bool.TryParse(claim.Value, out bool boolValue))
                return boolValue;

            if (claim.ValueType == ClaimValueTypes.Double && double.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double doubleValue))
                return doubleValue;

            if ((claim.ValueType == ClaimValueTypes.Integer || claim.ValueType == ClaimValueTypes.Integer32) && int.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out int intValue))
                return intValue;

            if (claim.ValueType == ClaimValueTypes.Integer64 && long.TryParse(claim.Value, out long longValue))
                return longValue;

            if (claim.ValueType == ClaimValueTypes.DateTime && DateTime.TryParse(claim.Value, out DateTime dateTimeValue))
                return dateTimeValue;

            if (claim.ValueType == Json)
                return JObject.Parse(claim.Value);

            if (claim.ValueType == JsonArray)
                return JArray.Parse(claim.Value);

            if (claim.ValueType == JsonNull)
                return string.Empty;

            return claim.Value;
        }

        /// <summary>
        /// Returns all <see cref="SecurityKey"/> provided in validationParameters.
        /// </summary>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>Returns all <see cref="SecurityKey"/> provided in validationParameters.</returns>
        internal static IEnumerable<SecurityKey> GetAllSigningKeys(TokenValidationParameters validationParameters)
        {
            LogHelper.LogInformation(TokenLogMessages.IDX10243);
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey key in validationParameters.IssuerSigningKeys)
                    yield return key;
        }

        /// <summary>
        /// Merges claims. If a claim with same type exists in both <paramref name="claims"/> and <paramref name="subjectClaims"/>, the one in claims will be kept.
        /// </summary>
        /// <param name="claims"> Collection of <see cref="Claim"/>'s.</param>
        /// <param name="subjectClaims"> Collection of <see cref="Claim"/>'s.</param>
        /// <returns> A Merged list of <see cref="Claim"/>'s.</returns>
        internal static IEnumerable<Claim> MergeClaims(IEnumerable<Claim> claims, IEnumerable<Claim> subjectClaims)
        {
            if (claims == null)
                return subjectClaims;

            if (subjectClaims == null)
                return claims;

            List<Claim> result = claims.ToList();

            foreach (Claim claim in subjectClaims)
            {
                if (!claims.Any(i => i.Type == claim.Type))
                    result.Add(claim);
            }

            return result;
        }
    }
}
