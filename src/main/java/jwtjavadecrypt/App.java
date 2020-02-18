package jwtjavadecrypt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.RSASSAVerifier;

public class App {
    
    // https://stackoverflow.com/questions/42482691/how-to-decrypt-a-jwt-in-java-which-is-encrypted-with-jwe-when-the-encrypted-to

    static String realmPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7r8kE6re8pBzowIznGJjQTFS/najgsUoi5VwMnU87f+m7DX0+9K+DgdazkgRS5T3guvGDmvnv4VfRT6sA5gDAtBrBs998xfZhOYHl/1dKzzhVLQHVl1W51X2hQL65HchhhZ7qG03iCDGPfdVXaKiZu9rLAivJCqldsjyiWt71v0i53m6pdu/ld3QHE0m6PBvAwpYlTiNqDvOP2J0JVGg0JAXYwZcL3PcqrFufyIYnXd7uIrnFYwO2T6t+5Uf/twYCBhTEusAtpBdFhpX5fQ5iCwCgGEvAEV3riO+xQyHTnL8R+Kddw/AIB0+0dExC0liyqimzMiyzbQOTw23vHweQIDAQAB";
    static String encryptedKey = "ma_clef_doit_faire_32_caracteres";

    static String jwtAccessTokenString = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjYzQ0I5ODFENUI1NjYyOTQxMThBNTREODhEOTBBQkVCOTE4RTcyQzQiLCJ0eXAiOiJKV1QifQ.eyJ1bmlxdWVfbmFtZSI6IklkVXNlci0xMjU2Iiwibm9tIjoiQXVyaW91IiwicHJlbm9tIjoiUGhpbGlwcGUiLCJuYmYiOjE1ODIwMTg1MTksImV4cCI6MjU4MjAxODUxOCwiaWF0IjoxNTgyMDE4NTE5LCJpc3MiOiJpZEFwcGxpY2F0aW9uIn0.U14zFR6NZBpoMkNX5BFTtA3bswDleEHyRAgErlgk82KHFcGHJb3xcvEVX-xo_GMgyVXPI0Ut8lrMaxylv7GaXP0Ji7HcFQURDA67ii_wxhOKDdpxZ0NGVfhzBWtRZ0NjxikuWadp-_juuNQKYoxjrpk_dAl5VSbDQ00ef4Us0CuNHfCrscYzmKV0CaBfq7p7CtLMY1PIoQCq8BYPyZwOHVZeg9Bs943Iwgj-ByM7N2Z9hgaTXdpGkX2bCngisy302kpx_O2gj5IdjVLJ_JFQ02YRANTbRapgYkHGSQUuTTd1wi4fByhx1s9-NOSnfE5xWDj79EN_PDqOM9BqDb4K9g";
    static String jweAccessTokenString = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldUIn0.tvWsJBng5qUZ-q0M4ct9uYXbHn-duxtb53REFPRUHVhnmUAXEjIu9vxn1E1jdiH-Tv0gIqeVCab8Qr-ZxQLZ8qomblt8501p.MjdwTNAAM_5rG7fEOngMng.ksUM0DnT3Gy6D1w_e3khpK1qZ4DFNK6684eLLWcvmep6UhnXyItScmaVnrwCxZsWC97iqGyKlBIeAZXyYblp7OFS_pEgoXoSdwghxiB0P0wDIuKQZMY5sAxd863mWT-tjfgZ50kr6kFliVdKBDXK7zJfD_FaTdBqAjcfehhYtbWRGbrkDfflA62ym2geJzCNfMljJ8840nqVeIp-N53p6mT2RdXJo8FsLafaQKUIdO_xa5g7sekywLUqMsP6xtDBU0EYnoEapOvay4yLBfbbojUBQMA9DvMiDtOkaMPlU9Rq7Jx6u2xu-ylQNnXFnbSx2U2qpwvoUX2oAdGU33Lzwy9jHevLMa2Iy2ULiy3hetye4U4kCESYmRwgEKTc1jWMNgEyrKpe0Sm-XJsxzgoYj24-PZABCtr87bs0t7LGqwjOY4See-35wusfWh4Yg-t-H7ZecBnbiu1CExX-e6mK26_UeuX1zA9dLRM8Pka9eosxlR6Nuut1kK-q0kS3Q1HPyXn5lMuS6SsyzaFR6XxwyshK5OYRnsC5Nv2LkfrUxctz5Jyk9mXOlBRFI6Y1JwsNZzBzFMZ3fQP7KGSjeTZpStcvbbO7kbkqxrmTOdzzlHjbs83B2VwLFPf3GkeYULe2Tgbjas2PbHNvsoDKOTyaueRiXzqR_3cBIXx_TjZl178alArDI7AVd1az6T2HUYQXWISoIasFddTwhkQGtKOFKmx-Qwz9fq2-Q3BLQiF-n2U4blRg3yGPamYA_7EiXzVhCHdvjHxmGuveGqd5Rc88pumu24KJG1f6XoR8SC3azlnbTKZwY-vbcblkXv5urHXGko97Myv-2EFGTnPiUrLWHw.S7yPQsfpLSa-8jcUdbV584eArVPUfeTy4G1D-KVMhu0";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException, IOException, ParseException {
        JWESample();
        JWTSample();
    }

    public static void JWTSample() throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = Jwts.parser().setSigningKey(GetPublicKey()).parseClaimsJws(jwtAccessTokenString).getBody();
        String userName = String.format("%s %s", claims.get("prenom", String.class), claims.get("nom", String.class));
        System.out.println("Hello " + userName);
    }

    public static void JWESample() throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        JWEObject jweObject = JWEObject.parse(jweAccessTokenString);
        byte[] decodedKey = encryptedKey.getBytes(); // si c'est du base64 : Base64.getDecoder().decode()
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        try {
            AESDecrypter decryptor = new AESDecrypter(key);
            jweObject.decrypt(decryptor);
            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

            if (!signedJWT.verify(new RSASSAVerifier(GetPublicKey())))
                throw new Exception("ERREUR : signature invalide !!");
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String userName = String.format("%s %s", claims.getClaim("prenom"), claims.getClaim("nom"));

            System.out.println("Hello " + userName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static RSAPublicKey GetPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(realmPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);
        return (RSAPublicKey)publicKey;
    }
}
