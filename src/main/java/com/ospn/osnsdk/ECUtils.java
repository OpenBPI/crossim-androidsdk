package com.ospn.osnsdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Random;

public class ECUtils {
    public static final String SIGN_ALGORITHM = "SHA256withECDSA";
    public static final String ECDSA = "ECDSA";
    public static final String PRIME_256V1 = "prime256v1";
    public static final String ALGORITHM = "EC";
    public static final String SPACE_NAME = "prime256v1";// prime256v1 secp256k1

    private static ECPublicKey getEcPulicKeyFromAddress(String address) {
        try {
            String flag = address.substring(0, 3);
            if (!flag.equals("OSN")) {
                OsnUtils.logInfo("OSNID format error");
                return null;
            }
            String OsnUtilsstr = address.substring(4);
            byte[] data = Base58.decode(OsnUtilsstr);
            byte[] pub = new byte[33];
            System.arraycopy(data, 2, pub, 0, 33);
            return getEcPublicKey(pub);
        } catch (Exception e) {
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private static ECPublicKey getEcPublicKeyFromPrivateKey(ECPrivateKey privateKey) {
        try {
            Provider provider = new BouncyCastleProvider();
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECParameterSpec ecSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            org.bouncycastle.math.ec.ECPoint Q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD());
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(Q, ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
            return publicKey;
        } catch (Exception e) {
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private static ECPublicKey getEcPublicKey(byte[] pubKey) {
        ECPublicKey pk;
        try {
            Provider provider = new BouncyCastleProvider();
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(SPACE_NAME);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, provider);
            org.bouncycastle.jce.spec.ECNamedCurveSpec params = new org.bouncycastle.jce.spec.ECNamedCurveSpec(SPACE_NAME, spec.getCurve(), spec.getG(), spec.getN());
            ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(params.getCurve(), pubKey);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
            return pk;
        } catch (Exception e) {
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private static ECPrivateKey getEcPrivateKey(byte[] priKey){
        try {
            Provider provider = new BouncyCastleProvider();
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, provider);
            ECPrivateKey privKey2 = (ECPrivateKey)kf.generatePrivate(new PKCS8EncodedKeySpec(priKey));
            return privKey2;
        } catch (Exception e) {
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private static byte[] ecDecrypt(ECPrivateKey privateKey, String data){
        try {
            byte[] rawData = Base58.decode(data);
            short keyLength = (short)((rawData[0]&0xff)|((rawData[1]&0xff)<<8));
            byte[] ecData = new byte[keyLength];
            System.arraycopy(rawData,2,ecData,0,keyLength);
            ecData = ecIESDecrypt(privateKey, ecData);

            byte[] aesKey = new byte[16];
            byte[] aesIV = new byte[16];
            byte[] aesData = new byte[rawData.length-keyLength-2];
            System.arraycopy(ecData,0,aesKey,0,16);
            System.arraycopy(ecData,16,aesIV,0,16);
            System.arraycopy(rawData,keyLength+2,aesData,0,rawData.length-keyLength-2);

            IvParameterSpec iv = new IvParameterSpec(aesIV);
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decData = cipher.doFinal(aesData);
            return decData;
            //return new String(decData);
        }catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    private static String ecEncrypt(ECPublicKey publicKey, byte[] data){
        byte[] aesKey = new byte[16];
        byte[] aesIV = new byte[16];
        Random random = new Random();
        for(int i = 0; i < 16; ++i){
            aesKey[i] = (byte)random.nextInt(256);
            aesIV[i] = 0;
        }
        try {
            IvParameterSpec iv = new IvParameterSpec(aesIV);
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encData = cipher.doFinal(data);

            byte[] encKey = new byte[32];
            System.arraycopy(aesKey,0,encKey,0,16);
            System.arraycopy(aesIV,0,encKey,16,16);
            byte[] encECKey = ecIESEncrypt(publicKey, encKey);

            byte[] eData = new byte[encECKey.length+encData.length+2];
            eData[0] = (byte)(encECKey.length&0xff);
            eData[1] = (byte)((encECKey.length)>>8&0xff);
            System.arraycopy(encECKey,0,eData,2,encECKey.length);
            System.arraycopy(encData,0,eData,encECKey.length+2,encData.length);
            return Base58.encode(eData);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    private static byte[] ecIESEncrypt(ECPublicKey pubkey, byte[] raw){
        try {
            //Cipher cipher = Cipher.getInstance("ECIESwithAES/NONE/PKCS7Padding",new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("ECIES",new BouncyCastleProvider());
            //Cipher cipher = Cipher.getInstance("ECIESwithAESCBC",new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            byte[] cipherText = cipher.doFinal(raw);
            return cipherText;
        } catch (Exception e){
            OsnUtils.logInfo(e.toString());
            return null;
        }
    }
    private static byte[] ecIESDecrypt(ECPrivateKey privateKey, byte[] raw){
        try {
            //Cipher cipher = Cipher.getInstance("ECIESwithAES/NONE/PKCS7Padding",new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("ECIES",new BouncyCastleProvider());
            //Cipher cipher = Cipher.getInstance("ECIESwithAESCBC",new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cipherText = cipher.doFinal(raw);
            return cipherText;
        } catch (Exception e){
            OsnUtils.logInfo(e.toString());
            return null;
        }
    }
    private static ArrayList<byte[]> GenSubKeys(){
        ArrayList<byte[]> arrayList = new ArrayList<>();
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(new ECGenParameterSpec("prime256v1"));
            KeyPair keyPair = kpg.generateKeyPair();
            org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey ku =
                    (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey)keyPair.getPublic();
            org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey kp = (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey)keyPair.getPrivate();
            byte[] encodedpoint = ku.getQ().getEncoded(true);
            byte[] privateKey = kp.getEncoded();
            arrayList.add(privateKey);
            arrayList.add(encodedpoint);
        } catch (Exception e){
            OsnUtils.logInfo(e.toString());
            return null;
        }
        return arrayList;
    }

    public static String HashOsnData(byte[] data){
        byte[] hash = OsnUtils.Sha256(data);
        return Base58.encode(hash);
    }
    public static String SignOsnData(String privkey, byte[] data){
        try {
            byte[] hash = OsnUtils.Sha256(data);
            ECPrivateKey privatekey = getEcPrivateKey(Base58.decode(privkey));
            Signature signer = Signature.getInstance(SIGN_ALGORITHM);
            signer.initSign(privatekey);
            signer.update(hash);
            byte[] signdata = signer.sign();
            return Base58.encode(signdata);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    public static String SignOsnHash(String privKey, String hash){
        try {
            ECPrivateKey privatekey = getEcPrivateKey(Base58.decode(privKey));
            byte[] hashData = Base58.decode(hash);
            Signature signer = Signature.getInstance(SIGN_ALGORITHM);
            signer.initSign(privatekey);
            signer.update(hashData);
            byte[] signdata = signer.sign();
            return Base58.encode(signdata);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static boolean VerifyOsnData(String osnID, byte[] data, String sign){
        try {
            byte[] hashData = OsnUtils.Sha256(data);
            byte[] signData = Base58.decode(sign);
            ECPublicKey pkey = ECUtils.getEcPulicKeyFromAddress(osnID);
            Signature ecdsaVerify = Signature.getInstance(SIGN_ALGORITHM, new BouncyCastleProvider());
            ecdsaVerify.initVerify(pkey);
            ecdsaVerify.update(hashData);
            return ecdsaVerify.verify(signData);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return false;
    }
    public static boolean VerifyOsnHash(String osnID, String hash, String sign){
        try {
            byte[] hashData = Base58.decode(hash);
            byte[] signData = Base58.decode(sign);
            ECPublicKey pkey = ECUtils.getEcPulicKeyFromAddress(osnID);
            Signature ecdsaVerify = Signature.getInstance(SIGN_ALGORITHM, new BouncyCastleProvider());
            ecdsaVerify.initVerify(pkey);
            ecdsaVerify.update(hashData);
            return ecdsaVerify.verify(signData);
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return false;
    }
    public static Boolean IsGroup(String osnid){
        String osnstr = osnid.substring(3);
        byte[] data = Base58.decode(osnstr);
        return data[1] == 1;
    }
    public static byte[] ECDecrypt(String priKey, String data){
        ECPrivateKey privateKey = getEcPrivateKey(Base58.decode(priKey));
        return ecDecrypt(privateKey, data);
    }
    public static String ECEncrypt(String osnID, byte[] data){
        ECPublicKey pubKey = getEcPulicKeyFromAddress(osnID);
        return ecEncrypt(pubKey, data);
    }
    public static String[] CreateOsnID(String type){
        try {
            ArrayList<byte[]> keyList1 = GenSubKeys();
            ArrayList<byte[]> keyList2 = GenSubKeys();
            byte[] pub2hash = OsnUtils.Sha256(keyList2.get(1));
            byte[] pubkey = keyList1.get(1);

            //byte[] address = new byte[1 + 1 + pubkey.length + pub2hash.length]; //version(1)|flag(1)|pubkey(33)|shadowhash(32)
            byte[] address = new byte[1 + 1 + pubkey.length];
            address[0] = 1;
            address[1] = 0;
            if (type.equalsIgnoreCase("group"))
                address[1] = 1;
            else if (type.equalsIgnoreCase("service"))
                address[1] = 2;
            System.arraycopy(pubkey, 0, address, 2, pubkey.length);
            //System.arraycopy(pub2hash, 0, address, pubkey.length+2, pub2hash.length);
            String addrString = "OSN" + Base58.encode(address);
            String priKey1 = Base58.encode(keyList1.get(0));
            String priKey2 = Base58.encode(keyList2.get(0));

            String[] osnID = {addrString, priKey1, priKey2};
            OsnUtils.logInfo(osnID[0]);
            return osnID;
        }
        catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }

    public static String EccAes2E(String osnID, byte[] data, String msgKey){
        try{
            ECPublicKey pubKey = getEcPulicKeyFromAddress(osnID);
            byte[] aesKey = new byte[16];
            byte[] aesIV = new byte[16];
            Random random = new Random();
            for(int i = 0; i < 16; ++i){
                aesKey[i] = (byte)random.nextInt(256);
                aesIV[i] = 0;
            }

            IvParameterSpec iv = new IvParameterSpec(aesIV);
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encData = cipher.doFinal(data);

            byte[] encKey = new byte[32];
            System.arraycopy(aesKey,0,encKey,0,16);
            System.arraycopy(aesIV,0,encKey,16,16);
            byte[] encECKey = ecIESEncrypt(pubKey, encKey);

            byte[] bMsgKey = Base58.decode(msgKey);
            key = new SecretKeySpec(bMsgKey, "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encMsgKey = cipher.doFinal(encKey);

            byte[] eData = new byte[encECKey.length+encMsgKey.length+encData.length+2];
            eData[0] = (byte)(encECKey.length&0xff);
            eData[1] = (byte)((encECKey.length)>>8&0xff);
            System.arraycopy(encECKey,0,eData,2,encECKey.length);
            System.arraycopy(encMsgKey,0,eData,2+encECKey.length,encMsgKey.length);
            System.arraycopy(encData,0,eData,2+encECKey.length+encMsgKey.length,encData.length);
            return Base58.encode(eData);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static byte[] EccAes2D(String priKey, String data, String msgKey){
        try{
            ECPrivateKey privateKey = getEcPrivateKey(Base58.decode(priKey));

            byte[] rawData = Base58.decode(data);
            short keyLength = (short)((rawData[0]&0xff)|((rawData[1]&0xff)<<8));
            byte[] ecData = new byte[keyLength];
            System.arraycopy(rawData,2,ecData,0,keyLength);
            ecData = ecIESDecrypt(privateKey, ecData);

            byte[] aesKey = new byte[16];
            byte[] aesIV = new byte[16];
            byte[] aesData = new byte[rawData.length-keyLength-48-2];
            System.arraycopy(ecData,0,aesKey,0,16);
            System.arraycopy(ecData,16,aesIV,0,16);
            System.arraycopy(rawData,keyLength+48+2,aesData,0,rawData.length-keyLength-48-2);

            IvParameterSpec iv = new IvParameterSpec(aesIV);
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decData = cipher.doFinal(aesData);
            return decData;
        }catch (Exception e){
            OsnUtils.logInfo(e.toString());
        }
        return null;
    }
    public static String ECEncrypt2(String osnID, byte[] data){
        ECPublicKey pubKey = getEcPulicKeyFromAddress(osnID);
        byte[] encData = ecIESEncrypt(pubKey, data);
        return Base58.encode(encData);
    }
    public static byte[] ECDecrypt2(String priKey, String data){
        ECPrivateKey privateKey = getEcPrivateKey(Base58.decode(priKey));
        return ecIESDecrypt(privateKey, Base58.decode(data));
    }
}
