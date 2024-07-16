package com.abah.ktpmodule;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.util.Base64;


public class Utility {
    private Context _context;
    SharedPreferences pref;
    SharedPreferences.Editor editor;
    private static final String PREF_NAME = "ektp";

    public Utility(Context context){
        this._context = context;
        pref = _context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        editor = pref.edit();

    }

    public static String byteArrayToBase64(byte[] imageData) {
        return Base64.getEncoder().encodeToString(imageData);
    }

    public static String convertBitmapToBase64(Bitmap bitmap) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, byteArrayOutputStream);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        return Base64.getEncoder().encodeToString(byteArray);
    }

    public byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 8),
                (byte)value};
    }

    public void SaveStringPreferences(String Keyname,String Value){
        try{
            editor.putString(Keyname, Value);
            editor.commit(); // commit changes
        }catch (Exception e) {
            e.printStackTrace();
            Log.d("aaa", "gagal SaveStringPreferences: "+e.getMessage());
        }
        //Log.d("aaa", "SaveStringPreferences("+Keyname+"):"+Value);
    }

    public void SaveIntPreferences(String Keyname,int Value){
        editor.putInt(Keyname, Value);
        editor.commit(); // commit changes
    }

    public String ReadStringPreferences(String Keyname){
        String ValReturn;
        ValReturn=pref.getString(Keyname, "");
        //Log.d("aaa", "ReadStringPreferences("+Keyname+"):"+ValReturn);
        return ValReturn;
    }

    public int ReadIntPreferences(String Keyname){
        int ValReturn;
        ValReturn=pref.getInt(Keyname, 0);
        return ValReturn;
    }

    public static byte[] HexStringToByteArray(String hex) {
        hex = hex.length()%2 != 0?"0"+hex:hex;

        byte[] b = new byte[hex.length() / 2];

        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String bytesToHexString(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();

        for (int j = 0; j < len; j++) {
            sb.append(String.format("%02x", bytes[j] & 0xff));
        }
        return sb.toString();
    }

    public String getHexStringFromByteArray(byte[] data) throws Exception
    {
        String szDataStr = "";
        for (int ii=0; ii < data.length; ii++)
        {
            szDataStr += String.format("%02X ", data[ii] & 0xFF);
        }
        return szDataStr;
    }

    static Bitmap makeTransparentBitmap(Bitmap bmp, int alpha) {
        Bitmap transBmp = Bitmap.createBitmap(bmp.getWidth(),
                bmp.getHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(transBmp);
        final Paint paint = new Paint();
        paint.setAlpha(alpha);
        canvas.drawBitmap(bmp, 0, 0, paint);
        return transBmp;
    }
    static String toBinary(final byte b) {
        return String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
    }

    static byte[] decompress(final byte[] data, final int width, final int height) {
        final byte[] result = new byte[width * height];
        final int compWidth = width / 8;
        for (int i = 0; i < height; ++i) {
            for (int j = 0; j < compWidth; ++j) {
                final byte num3 = data[i * compWidth + j];
                final int num4 = i * width + j * 8;
                final String s = toBinary(num3);
                for (int k = 0; k < 8; ++k) {
                    result[num4 + k] = (byte)((s.charAt(k) == '1') ? 255 : 0);
                }
            }
        }
        return result;
    }

    static Bitmap decompressToImage(final byte[] data, final int width, final int height) {
        final byte[] decBytes = decompress(data, width, height);
        Bitmap bitmap = Bitmap.createBitmap(width,height, Bitmap.Config.RGB_565);
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                final int rgb = decBytes[y * width + x] << 16 | decBytes[y * width + x] << 8 | decBytes[y * width + x];
                bitmap.setPixel(x,y,rgb);
            }
        }
        return bitmap;
    }




}
