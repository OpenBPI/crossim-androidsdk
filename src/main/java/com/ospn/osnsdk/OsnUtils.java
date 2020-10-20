package com.ospn.osnsdk;

import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.os.Environment;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OsnUtils {
    public static String mLogName = "OsnSDK.log";
    public static BufferedOutputStream mLogger = null;
    @SuppressLint("SimpleDateFormat")
    private static SimpleDateFormat mFormater= new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss] ");
//    private static String mIV = "0123456789abcdef";

    public static byte[] Sha256(byte[] data){
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data);
            data = messageDigest.digest();
        } catch (Exception e){
            e.printStackTrace();
        }
        return data;
    }
    public static String aesEncrypt(byte[] data, byte[] key){
        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] encData = cipher.doFinal(data);
            return Base58.encode(encData);
        }
        catch (Exception e){
            e.printStackTrace();
            logInfo(e.toString());
        }
        return null;
    }
//    public static String aesEncrypt(String data, byte[] key){
//        return aesEncrypt(data.getBytes(), key);
//    }
    public static String aesEncrypt(String data, String key){
        byte[] pwdHash = Sha256(key.getBytes());
        return aesEncrypt(data.getBytes(), pwdHash);
    }
    public static byte[] aesDecrypt(byte[] data, byte[] key){
        try {
            byte[] iv = new byte[16];
            Arrays.fill(iv,(byte)0);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        }
        catch (Exception e){
            e.printStackTrace();
            logInfo(e.toString());
        }
        return null;
    }
//    public static byte[] aesDecrypt(String data, byte[] key){
//        byte[] decData = Base58.decode(data);
//        return aesDecrypt(decData, key);
//    }
    public static String aesDecrypt(String data, String key){
        byte[] pwdHash = Sha256(key.getBytes());
        byte[] decData = Base58.decode(data);
        decData = aesDecrypt(decData,pwdHash);
        return new String(decData);
    }
    public static byte[] getAesKey(){
        byte[] key = new byte[16];
        Random random = new Random();
        for(int i = 0; i < 16; ++i)
            key[i] = (byte)random.nextInt(256);
        return key;
    }

    public static JSONObject makeMessage(String command, String from, String to, JSONObject data){
        try {
            JSONObject json = new JSONObject();
            json.put("command", command);
            json.put("from", from);
            json.put("to", to);
            json.put("content", data==null?new JSONObject():data);
            json.put("timestamp", String.valueOf(System.currentTimeMillis()));
            json.put("crypto", "none");
            return json;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static JSONObject makeMessage(String command, String from, String to, JSONObject data, String key, boolean isMsg){
        try {
            JSONObject json = new JSONObject();
            json.put("command", command);
            json.put("from", from);
            json.put("to", to);

            if(data == null)
                data = new JSONObject();

            byte[] aesKey = getAesKey();
            String encData = aesEncrypt(data.toString().getBytes(Charset.forName("utf-8")), aesKey);
            json.put("content", encData);

            long timestamp = System.currentTimeMillis();
            String calc = from + to + timestamp + encData;
            String hash = ECUtils.HashOsnData(calc.getBytes());
            json.put("hash", hash);
            json.put("timestamp", timestamp);

            if(key != null) {
                String sign = ECUtils.SignOsnHash(key, hash);
                json.put("sign", sign);
            }

            String encKey = ECUtils.ECEncrypt2(to, aesKey);
            json.put("ecckey", encKey);

            if(isMsg) {
                byte[] msgKey = Sha256(key.getBytes());
                encKey = aesEncrypt(aesKey, msgKey);
                json.put("ecckey2", encKey);
                json.put("crypto", "ecc-aes2");
            }
            else
                json.put("crypto", "ecc-aes");
            return json;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public static JSONObject takeMessage(JSONObject json, String key){
        try {
            byte[] data;
            byte[] aesKey;
            String crypto = json.getString("crypto");
            if(crypto.equalsIgnoreCase("none"))
                return JSON.parseObject(json.getString("content"));
            else if(crypto.equalsIgnoreCase("ecc-aes2") && json.getString("from").equalsIgnoreCase(OSNManager.Instance().getUserID())){
                data = Base58.decode(json.getString("ecckey2"));
                aesKey = aesDecrypt(data, Sha256(key.getBytes()));
            }
            else
                aesKey = ECUtils.ECDecrypt2(key, json.getString("ecckey"));
            data = Base58.decode(json.getString("content"));
            data = aesDecrypt(data, aesKey);
            return JSON.parseObject(new String(data, Charset.forName("utf-8")));
        }
        catch (Exception e){
            logInfo(e.toString());
        }
        return null;
    }
//    public static JSONObject makeMessage(String command, String from, String to, JSONObject content){
//        try {
//            JSONObject json = new JSONObject();
//            json.put("command", command);
//            json.put("from", from);
//            json.put("to", to);
//
//            if(content != null){
//                String time = content.getString("timestamp");
//                if(time == null)
//                    time = String.valueOf(System.currentTimeMillis());
//                String data = from + to + time;
//                String hash = ECUtils.HashOsnData(data.getBytes());
//                content.put("hash", hash);
//
//                String encData = ECUtils.ECEncrypt(to, content.toString().getBytes());
//                json.put("timestamp", time);
//                json.put("content", encData);
//                json.put("crypto", "ecc-aes");
//            }
//            return json;
//        }
//        catch (Exception e){
//            e.printStackTrace();
//        }
//        return null;
//    }
//    public static JSONObject takeMessage(JSONObject json, String privateKey, String msgKey){
//        try {
//            String content = json.getString("content");
//            if(content == null)
//                return null;
//            String crypt = json.getString("crypto");
//            if(crypt.equalsIgnoreCase("ecc-aes")) {
//                byte[] rawData = ECUtils.ECDecrypt(privateKey, content);
//                return JSON.parseObject(new String(rawData));
//            }
//            byte[] rawData = ECUtils.EccAes2D(privateKey, content, msgKey);
//            return JSON.parseObject(new String(rawData));
//        }
//        catch (Exception e){
//            logInfo(e.toString());
//        }
//        return null;
//    }
    static public void logInfo(String info){
        try{
//            if(mLogger == null)
//                mLogger = new BufferedOutputStream(new FileOutputStream(mLogName));
            Date date = new Date(System.currentTimeMillis());
            String time = mFormater.format(date);
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            String traceInfo = "["+Thread.currentThread().getId()+" " + stackTrace[3].getClassName() + "." + stackTrace[3].getMethodName() + "] ";
//            mLogger.write(time.getBytes());
//            mLogger.write(traceInfo.getBytes());
//            if(info != null)
//                mLogger.write(info.getBytes());
//            mLogger.write("\r\n".getBytes());

            System.out.print(time);
            System.out.print(traceInfo);
            System.out.println(info);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
