package com.abah.ktpmodule;

import static com.abah.ktpmodule.Utility.HexStringToByteArray;
import static com.abah.ktpmodule.Utility.byteArrayToBase64;
import static com.abah.ktpmodule.Utility.bytesToHexString;
import static com.abah.ktpmodule.Utility.convertBitmapToBase64;
import static com.abah.ktpmodule.Utility.decompressToImage;
import static com.abah.ktpmodule.Utility.makeTransparentBitmap;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcelable;
import android.provider.Settings;
import android.util.Log;
import android.nfc.Tag;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt3.Mqtt3AsyncClient;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/*
Buka terminal di Android Studio.
./gradlew :ktpmodule:assembleRelease

 */
public class EKTP {
    WeakReference<Context> ctx;
    private static final String TAG = "ektp";

    public static final int CARD_TYPE_NO = 0x00;

    public static final int ISODEP_CARD = 0x01;
    public static final int MIFARE_CARD = 0x02;

    public static final byte CMD_MUTUAL_AUTH = 0x30;
    public static final byte CMD_VERIFY_MUTUAL_AUTH = 0x31;
    public static final byte CMD_VERIFY_SIGN = 0x32;
    public static final byte CMD_VERIFY_SIGN2 = 0x33;
    public static final byte CMD_ENCODE_SM = 0x34;
    public static final byte CMD_DECODE_SM = 0x35;
    public static final byte CMD_ECD_SIGN = 0x36;
    public static final byte CMD_START_MINUTIAE1 = 0x37;
    public static final byte CMD_START_MINUTIAE2 = 0x38;
    public static final byte CMD_START_SIGNATURE = 0x39;

    private byte sourceID = 0, destID = 0;
    private byte LengthDataToSam=0,CommandToSam;
    private int MaximumBuffer = 0x60;
    private Mqtt3AsyncClient mqttClient;
    private KtpListener callbackListener;
    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFiltersArray;
    private String[][] techListsArray;
    private byte[] byteUID = new byte[8];

    byte TaskID;
    enum task_demog {SELECT_ECDSASIGN,READ_DATA_ECDSASIGN,SELECT_EF_DEMOG,READ_SIZE,READ_DATA,SELECT_EF_MINUTIAE1,READ_SIZE_MINUTIAE1,READ_DATA_MINUTIAE1,SELECT_EF_MINUTIAE2,READ_SIZE_MINUTIAE2,READ_DATA_MINUTIAE2,SELECT_EF_SIGNATURE,READ_SIZE_SIGNATURE,READ_DATA_SIGNATURE,ACTIVATED_SELECT,ACTIVATED_PROCESS,FINISH};
    byte[] readBuffComplete=null;
    byte[] Minutiae1Complete=null;
    byte[] Minutiae2Complete=null;
    byte[] SignatureComplete=null;
    int DemoGraphicSize,OffsetRead,Minutiae1Size,Minutiae2Size,SignatureSize;

    private byte[] byteAPDU = null;
    private byte[] respAPDU = null;
    private byte[] BuffToSam = null;
    private boolean isConnected=false;
    String strUniqueNumber,strSamId;
    String strBuildModel= Build.MANUFACTURER+"_"+Build.DEVICE;
    String strExtdata="2";  ////1=demog, 2=demog+sign, 3=demog+menutiae, 4=AllData=demog+sign+menutiae
    String strToken="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI4NTMwMGMxNTMxZWNiZTAwIiwiYXVkIjpbIkdST1VQIiwiRGV2ZWwgQWJhaCIsImluaSB0b2tlbiB1bnR1ayBleHBlcmltZW50IEFiYWgiXSwiaXNzIjoiYWJhaC5ldG95Lmthc2VwIiwiZXhwIjoxNzUwMDg0OTE1LCJpYXQiOjE3MTg1NDg5MTUsImp0aSI6ImI3NjlhODQ5LTQyNWEtNGNjOC1iMGM4LThmMzVjY2NiYWZlYyJ9.20D3SjeKFwx8t6KpJclosvVu0kA_zKCKqX5_4SA0oiQ";

    private Handler handler;
    Runnable periodicPublishRunnable;
    int cntSecond=0;
    IsoDep myTag;
    Utility utilclass;

    public EKTP(Context ctx) {
        this.ctx = new WeakReference<>(ctx);
        utilclass = new Utility(ctx);
        strUniqueNumber = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        mqttClient = MqttClient.builder()
                .useMqttVersion3()
                .serverHost("103.142.95.150")
                .serverPort(1993)
                .addConnectedListener(context -> {
                    isConnected=true;
                })
                .addDisconnectedListener(context -> {
                    isConnected=false;
                    connectToMqttBroker();
                })
                .buildAsync();
        connectToMqttBroker();
        // Inisialisasi NFC
        nfcAdapter = NfcAdapter.getDefaultAdapter(ctx);

        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        try {
            ndef.addDataType("*/*");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("Failed to add MIME type", e);
        }
        intentFiltersArray = new IntentFilter[]{ndef};
        techListsArray = new String[][]{new String[]{NfcA.class.getName()}, new String[]{NfcB.class.getName()}};

        handler = new Handler();
        startPeriodicPublish();
        Intent intent = new Intent(ctx, ctx.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        pendingIntent = PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_MUTABLE);
    }

    // NFC Handling
    public void enableForegroundDispatch(AppCompatActivity activity) {
        nfcAdapter.enableForegroundDispatch(activity, pendingIntent, intentFiltersArray, techListsArray);
    }

    public void disableForegroundDispatch(AppCompatActivity activity) {
        nfcAdapter.disableForegroundDispatch(activity);
    }

    private static byte[] atohex(String data){
        String hexchars = "0123456789abcdef";

        data = data.replaceAll(" ","").toLowerCase();
        if (data == null)
        {
            return null;
        }
        byte[] hex = new byte[data.length() / 2];

        for (int ii = 0; ii < data.length(); ii += 2)
        {
            int i1 = hexchars.indexOf(data.charAt(ii));
            int i2 = hexchars.indexOf(data.charAt(ii + 1));
            hex[ii/2] = (byte)((i1 << 4) | i2);
        }
        return hex;
    }

    private byte[]  transceives (byte[] data){
        byte[] ra = null;

        try{
            ra = myTag.transceive(data);
        }catch (Exception e){
            Log.d(TAG,  "transceives: "+ e.getMessage());
        }
        return (ra);
    }


    private byte[] ReadPhotoGraph(){
        try {
            int MaximumBufferPhoto=250;
            byteAPDU = atohex("00A40000026FF2");
            //Log.d("abah", "selectEFPhotoGraph: " + getHexString(byteAPDU));
            respAPDU = transceives(byteAPDU);
            //Log.d("abah", "Response: " + getHexString(respAPDU));
            if (((respAPDU[respAPDU.length-2] & 0xFF)==0x90)&&((respAPDU[respAPDU.length-1] & 0xFF)==0x00)){
                byteAPDU = atohex("00B0000002");    //ambil PhotoGraphSize (2 byte)
                //Log.d("abah", "readEFPhotoGraph: " + getHexString(byteAPDU));
                respAPDU = transceives(byteAPDU);
                //Log.d("abah", "Response: " + getHexString(respAPDU));
                if (((respAPDU[respAPDU.length-2] & 0xFF)==0x90)&&((respAPDU[respAPDU.length-1] & 0xFF)==0x00)){
                    //2 byte awal adalah PhotoGraphSize, bukan data!!
                    int PhotoGraphSize=((respAPDU[0] & 0xFF) << 8) |((respAPDU[1] & 0xFF) << 0);
                    //Log.d("abah", "PhotoGraphSize: "+PhotoGraphSize);
                    byte[] PhotoGraphData=new byte[PhotoGraphSize];
                    byte[] readBuffCmd=atohex("00B0");
                    byte[] readBuffPhotoGraph=new byte[readBuffCmd.length+3];
                    System.arraycopy(readBuffCmd, 0, readBuffPhotoGraph, 0, readBuffCmd.length);
                    for (int i=2;i<PhotoGraphSize+2;i+=MaximumBufferPhoto){
                        if (i + MaximumBufferPhoto > PhotoGraphSize){
                            readBuffPhotoGraph[2]=(byte)((i >> 8) & 0xff);
                            readBuffPhotoGraph[3]=(byte)((i >> 0) & 0xff);
                            readBuffPhotoGraph[4]=(byte)(PhotoGraphSize-i+2);
                        }else{
                            readBuffPhotoGraph[2]=(byte)((i >> 8) & 0xff);
                            readBuffPhotoGraph[3]=(byte)((i >> 0) & 0xff);
                            readBuffPhotoGraph[4]=(byte)MaximumBufferPhoto;
                        }
                        //Log.d("abah", "readBuffPhotoGraph: "+getHexString(readBuffPhotoGraph));
                        respAPDU = transceives(readBuffPhotoGraph);
                        //Log.d("abah", "Response: " + getHexString(respAPDU));
                        if (((respAPDU[respAPDU.length-2] & 0xFF)==0x90)&&((respAPDU[respAPDU.length-1] & 0xFF)==0x00)){
                            System.arraycopy(respAPDU, 0, PhotoGraphData, i-2, respAPDU.length-2);
                        }
                    }
                    //Log.d("abah", "PhotoGraphData: "+getHexString(PhotoGraphData));
                    return PhotoGraphData;
                }
            }
        } catch (Exception e) {
            Log.d(TAG,  "ReadPhotoGraph: "+ e.getMessage());
        }
        return null;
    }

    private int SendPhotoToDb(byte[] datanya,int datalength){
        try {
            JSONObject jsnTxd= new JSONObject();
            jsnTxd.put("rdrid", strUniqueNumber);
            jsnTxd.put("carduid", bytesToHexString(byteUID,byteUID.length));
            jsnTxd.put("length", String.valueOf(datalength));
            jsnTxd.put("data", bytesToHexString(datanya,datalength));
            jsnTxd.put("rcode", "00");
            publish("ektp/savephoto",jsnTxd.toString());
        } catch (Exception e) {
            Log.d(TAG,  "SendPhotoToDb: "+ e.getMessage());
        }
        return 0;
    }


    private int sendAuthToServer(byte[] datanya,int datalength,byte command) {
        try {
            JSONObject jsnTxd= new JSONObject();
            jsnTxd.put("samid", strSamId);
            jsnTxd.put("rdrid", strUniqueNumber);
            jsnTxd.put("cmd", String.format("%02X", command));
            jsnTxd.put("length", String.valueOf(datalength*2));
            jsnTxd.put("data", bytesToHexString(datanya,datalength));
            jsnTxd.put("rcode", "00");
            publish("ektp/auth-"+strSamId,jsnTxd.toString());
            return 0;
        } catch (Exception e) {
            Log.d("abah",  "sendAuthToServer:"+e.getMessage());
        }
        return -1;
    }

    private int sendFreeStatus() {
        try {
            if (myTag.isConnected()) {
                myTag.close();
            }
            JSONObject jsnTxd= new JSONObject();
            jsnTxd.put("samid", strSamId);
            jsnTxd.put("rdrid", strUniqueNumber);
            jsnTxd.put("rcode", "99");  //force to FREE status
            publish("ektp/auth-"+strSamId,jsnTxd.toString());
            return 0;
        } catch (Exception e) {
            Log.d("abah",  "sendFreeStatus:"+e.getMessage());
        }
        return -1;
    }

    private int sendPing(String pingStatus) {
        try {
            JSONObject jsnTxd= new JSONObject();
            jsnTxd.put("rdrid", strUniqueNumber);
            jsnTxd.put("devtype", "KTPREADER");
            jsnTxd.put("status", pingStatus);
            jsnTxd.put("model", strBuildModel);
            jsnTxd.put("ver", "v.101");
            publish("ektp/ping",jsnTxd.toString());
        } catch (Exception e) {
            Log.d(TAG,  "sendPing: "+ e.getMessage());
        }
        return 0;
    }

    private int sendFindSam(String extdata) {
        try {
            JSONObject jsnTxd= new JSONObject();
            jsnTxd.put("rdrid", strUniqueNumber);
            jsnTxd.put("devtype", "KTPREADER");
            jsnTxd.put("model", strBuildModel);
            jsnTxd.put("carduid", bytesToHexString(byteUID,byteUID.length));
            jsnTxd.put("token", strToken);
            jsnTxd.put("extdata", strExtdata); //1=demog, 2=demog+sign, 3=demog+menutiae, 4=AllData=demog+sign+menutiae
            jsnTxd.put("authsam", true);    //false-->jika ada di db tdk perlu authsam, true--> selalu authsam
            publish("ektp/findsam",jsnTxd.toString());
        } catch (Exception e) {
            Log.d(TAG,  "sendFindSam: "+ e.getMessage());
        }
        return 0;
    }

    public void handleNfcIntent(Tag tag,byte[] uid) {
        cntSecond=0;    //hold dulu ping ke mqtt
        byte[] byteAPDU = null;
        byte[] respAPDU = null;

        myTag = IsoDep.get(tag);
        if (myTag != null) {
            try {
                if(!myTag.isConnected()){
                    try{
                        myTag.connect();
                        myTag.setTimeout(20000);
                    }catch (Exception e){
                        Log.d(TAG, "myTag.connect: " + e.getMessage());
                    }
                }

                if (myTag.isConnected()) {
                    try{
                        byteAPDU = atohex("00A40000027F0A");
                        //Log.d(TAG,  "SelectDFKTP: " + utilclass.getHexStringFromByteArray(byteAPDU));
                        respAPDU = transceives(byteAPDU);
                        //Log.d(TAG, "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                        if (((respAPDU[respAPDU.length - 2] & 0xFF) == 0x90) && ((respAPDU[respAPDU.length - 1] & 0xFF) == 0x00)) {
                            byteAPDU = atohex("00DF000000");
                            //Log.d(TAG, "GetCUIDB: " + utilclass.getHexStringFromByteArray(byteAPDU));
                            respAPDU = transceives(byteAPDU);
                            //Log.d(TAG, "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                            if (((respAPDU[respAPDU.length - 2] & 0xFF) == 0x90) && ((respAPDU[respAPDU.length - 1] & 0xFF) == 0x00)) {
                                //Log.d(TAG, "Card Type B");
                                System.arraycopy(respAPDU, (respAPDU.length) - 10, byteUID, 0, 8);
                            }else{
                               // Log.d(TAG, "Card Type A");
                            }
                            //Log.d(TAG,  "byteUID: " + utilclass.getHexStringFromByteArray(byteUID));

                            byteAPDU = atohex("00A40000026FF0");
                            //Log.d(TAG, "SelectEFCardControl: " + utilclass.getHexStringFromByteArray(byteAPDU));
                            respAPDU = transceives(byteAPDU);
                            //Log.d(TAG, "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                            if (((respAPDU[respAPDU.length - 2] & 0xFF) == 0x90) && ((respAPDU[respAPDU.length - 1] & 0xFF) == 0x00)) {
                                byteAPDU = atohex("00B0000036");
                                //Log.d(TAG, "GetCardControl: " + utilclass.getHexStringFromByteArray(byteAPDU));
                                respAPDU = transceives(byteAPDU);
                                //Log.d(TAG, "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                                if (((respAPDU[respAPDU.length - 2] & 0xFF) == 0x90) && ((respAPDU[respAPDU.length - 1] & 0xFF) == 0x00)) {
                                    byte[] arrLength = new byte[2];
                                    arrLength[0] = respAPDU[0];
                                    arrLength[1] = respAPDU[1];
                                    int intLength = 0;
                                    intLength = ((arrLength[0] & 0xFF) << 8) | ((arrLength[1] & 0xFF) << 0);
                                    //Log.d(TAG,"intLength:"+intLength);
                                    byte[] arrCardControlData = new byte[intLength + byteUID.length];
                                    System.arraycopy(respAPDU, 2, arrCardControlData, 0, intLength);
                                    System.arraycopy(byteUID, 0, arrCardControlData, intLength, byteUID.length);
                                    //Log.d(TAG,"arrCardControlData: "+utilclass.getHexStringFromByteArray(arrCardControlData));
                                    byte[] DataFoto = ReadPhotoGraph();
                                    //Log.d(TAG,"DataFoto: "+utilclass.getHexStringFromByteArray(DataFoto));
                                    if (DataFoto.length>200){
                                        SendPhotoToDb(DataFoto,DataFoto.length);
                                        byte[] bytePhoto = Arrays.copyOfRange(DataFoto, 2, DataFoto.length-2);
                                        String base64Image = byteArrayToBase64(bytePhoto);
                                        callbackListener.onReadPhoto(base64Image); //kirim ke Main Program

                                        byteAPDU = atohex("0084000008");
                                        try {
                                            //Log.d("abah", "GetChallenge: " + utilclass.getHexStringFromByteArray(byteAPDU));
                                            respAPDU = transceives(byteAPDU);
                                            //Log.d("abah", "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                                            if (((respAPDU[respAPDU.length - 2] & 0xFF) == 0x90) && ((respAPDU[respAPDU.length - 1] & 0xFF) == 0x00)) {
                                                byte[] mutualAuthCmd = atohex("00F10001");    //secMutualAuth
                                                CommandToSam = CMD_MUTUAL_AUTH;
                                                LengthDataToSam = (byte) (mutualAuthCmd.length + 1 + arrCardControlData.length + respAPDU.length - 2);
                                                BuffToSam = new byte[LengthDataToSam];
                                                System.arraycopy(mutualAuthCmd, 0, BuffToSam, 0, mutualAuthCmd.length);
                                                BuffToSam[mutualAuthCmd.length] = (byte) (arrCardControlData.length + respAPDU.length - 2);
                                                System.arraycopy(arrCardControlData, 0, BuffToSam, mutualAuthCmd.length + 1, arrCardControlData.length);
                                                System.arraycopy(respAPDU, 0, BuffToSam, mutualAuthCmd.length + 1 + arrCardControlData.length, respAPDU.length - 2);
                                                //Log.d(TAG, "BuffToSam: " + utilclass.getHexStringFromByteArray(BuffToSam));
                                                sendFindSam(strExtdata);
                                            }
                                        } catch (Exception e) {
                                            Log.d(TAG, "Read ControlData: " + e.getMessage());
                                        }
                                    }
                                }
                            }
                        }
                    }catch (Exception e){
                        Log.d(TAG, "ReadKtp: " + e.getMessage());
                    }
                }else{
                    Log.d(TAG, "myTag can't connected");
                }
            } finally {
                /*try {
                    myTag.close();
                } catch (IOException e) {
                    Log.e(TAG, "Error closing NFC connection", e);
                }*/
            }
        }
    }

    public void setConfig(String token,String extData) {
        //extdata --> 1=demog, 2=demog+sign, 3=demog+menutiae, 4=AllData=demog+sign+menutiae

    }

    public void setCallbackListener(KtpListener callbackListener) {
        this.callbackListener = callbackListener;
    }

    private void connectToMqttBroker() {
        try{
            mqttClient.connectWith()
                    .simpleAuth()
                    .username("root") // Ganti dengan username Anda
                    .password("17081945".getBytes()) // Ganti dengan password Anda
                    .applySimpleAuth()
                    .keepAlive(15)
                    .send()
                    .whenComplete((connAck, throwable) -> {
                        if (throwable != null) {
                            Log.e(TAG, "connectToMqttBroker", throwable);
                            if (!mqttClient.getState().isConnectedOrReconnect()) {
                                scheduleReconnect(); // Jadwalkan koneksi ulang
                            }
                        } else {
                            setupSubscription("ektp/findsamres-" + strUniqueNumber);
                            setupSubscription("ektp/authres-" + strUniqueNumber);
                            setupSubscription("ektp/hbeatres-" + strUniqueNumber);
                            setupSubscription("ektp/demogdb-" + strUniqueNumber);
                            setupSubscription("ektp/signdb-" + strUniqueNumber);
                            cntSecond=100;
                        }
                    });
        }catch (Exception e){
            Log.d(TAG, "connectToMqttBroker: "+e.getMessage());
            callbackListener.onMessageReceived("error/ektp", e.getMessage());
        }
    }

    private void scheduleReconnect() {
        // Cobalah untuk menghubungkan kembali setelah beberapa detik
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Tunggu 5 detik sebelum mencoba menghubungkan kembali
                connectToMqttBroker(); // Coba sambungkan kembali
            } catch (InterruptedException e) {
                Log.e(TAG, "Reconnect thread interrupted", e);
            }
        }).start();
    }

    private int Transaksi(byte[] rxdPacket, byte Cmd) {
        try{
            if (Cmd == CMD_MUTUAL_AUTH) {
                if (((rxdPacket[rxdPacket.length-2] & 0xFF)==0x90)&&((rxdPacket[rxdPacket.length-1] & 0xFF)==0x00)){
                    byte[] ExternalAuthCmd = atohex("0082000028");
                    byte[] ExternalAuth = new byte[ExternalAuthCmd.length+rxdPacket.length-2];
                    System.arraycopy(ExternalAuthCmd, 0, ExternalAuth, 0, ExternalAuthCmd.length);
                    System.arraycopy(rxdPacket, 0, ExternalAuth, ExternalAuthCmd.length, rxdPacket.length-2);
                    //Log.d(TAG,"ExternalAuth: "+utilclass.getHexStringFromByteArray(ExternalAuth));
                    respAPDU = transceives(ExternalAuth);
                    //Log.d(TAG, "Response: " + utilclass.getHexStringFromByteArray(respAPDU));
                    if (((respAPDU[respAPDU.length-2] & 0xFF)==0x90)&&((respAPDU[respAPDU.length-1] & 0xFF)==0x00)){
                        byte[] VerifyMutualAuthCmd = atohex("00F2000028");
                        byte[] VerifyMutualAuth = new byte[VerifyMutualAuthCmd.length+respAPDU.length-2];
                        System.arraycopy(VerifyMutualAuthCmd, 0, VerifyMutualAuth, 0, VerifyMutualAuthCmd.length);
                        System.arraycopy(respAPDU, 0, VerifyMutualAuth, VerifyMutualAuthCmd.length, respAPDU.length-2);
                        //Log.d(TAG, "VerifyMutualAuth: "+utilclass.getHexStringFromByteArray(VerifyMutualAuth));
                        TaskID= (byte) task_demog.SELECT_ECDSASIGN.ordinal();
                        sendAuthToServer(VerifyMutualAuth,VerifyMutualAuth.length,CMD_VERIFY_MUTUAL_AUTH);
                    }else {
                        sendFreeStatus();
                    }
                }else{
                    sendFreeStatus();
                }
            }else if (Cmd == CMD_ENCODE_SM){
                if (((rxdPacket[rxdPacket.length-2] & 0xFF)==0x90)&&((rxdPacket[rxdPacket.length-1] & 0xFF)==0x00)){
                    byteAPDU=new byte[rxdPacket.length-2];
                    System.arraycopy(rxdPacket, 0, byteAPDU, 0, rxdPacket.length-2);
                    //Log.d(TAG,"CMD_ENCODE_SM: "+getHexString(byteAPDU));
                    respAPDU = transceives(byteAPDU);
                    //Log.d(TAG, "Ektp res: " + getHexString(respAPDU));
                    if (((respAPDU[respAPDU.length-2] & 0xFF)==0x90)&&((respAPDU[respAPDU.length-1] & 0xFF)==0x00)){
                        byte[] DecodeSMCmd = atohex("00F40000");
                        byte[] DecodeSM = new byte[DecodeSMCmd.length+1+respAPDU.length-2];
                        System.arraycopy(DecodeSMCmd, 0, DecodeSM, 0, DecodeSMCmd.length);
                        DecodeSM[DecodeSMCmd.length]= (byte) (respAPDU.length-2);
                        System.arraycopy(respAPDU, 0, DecodeSM, DecodeSMCmd.length+1, respAPDU.length-2);
                        //Log.d(TAG, "DecodeSM: "+getHexString(DecodeSM));
                        sendAuthToServer(DecodeSM,DecodeSM.length,CMD_DECODE_SM);
                    }else {
                        sendFreeStatus();
                    }
                }else {
                    sendFreeStatus();
                }
            }else if (Cmd == CMD_DECODE_SM){
                if (((rxdPacket[rxdPacket.length-4] & 0xFF)==0x90)&&((rxdPacket[rxdPacket.length-3] & 0xFF)==0x00)&&((rxdPacket[rxdPacket.length-2] & 0xFF)==0x90)&&((rxdPacket[rxdPacket.length-1] & 0xFF)==0x00)){

                    byte[] readBuffCmd=atohex("00B0");
                    byte[] readBuffer=new byte[readBuffCmd.length+3];
                    System.arraycopy(readBuffCmd, 0, readBuffer, 0, readBuffCmd.length);

                    if (TaskID==(byte) task_demog.SELECT_ECDSASIGN.ordinal()){
                        //Log.d(TAG, "TaskID = SELECT_ECDSASIGN" );
                        TaskID= (byte) task_demog.SELECT_EF_DEMOG.ordinal(); //kalo sukses --> lanjut ke select Demog
                        byte[] ReadSizeCmd = atohex("00B0000050");
                        sendAuthToServer(ReadSizeCmd,ReadSizeCmd.length,CMD_ECD_SIGN);
                    }else if (TaskID==(byte) task_demog.SELECT_EF_DEMOG.ordinal()){
                        //Log.d(TAG, "TaskID = SELECT_EF_DEMOG" );
                        TaskID= (byte) task_demog.READ_SIZE.ordinal();
                        byte[] ReadSizeCmd = atohex("00B0000002");
                        sendAuthToServer(ReadSizeCmd,ReadSizeCmd.length,CMD_ENCODE_SM);
                    }else if (TaskID==(byte) task_demog.READ_SIZE.ordinal()){
                        //Log.d(TAG, "TaskID = READ_SIZE" );
                        TaskID= (byte) task_demog.READ_DATA.ordinal();
                        DemoGraphicSize=((rxdPacket[0] & 0xFF) << 8) |((rxdPacket[1] & 0xFF) << 0);
                        //Log.d(TAG,"DemoGraphicSize: "+DemoGraphicSize);
                        System.arraycopy(readBuffCmd, 0, readBuffer, 0, readBuffCmd.length);
                        OffsetRead=2;
                        readBuffComplete=new byte[DemoGraphicSize];
                        byte[] readStartOffset=atohex("00B00002D0");
                        readStartOffset[4]=(byte)MaximumBuffer;
                        sendAuthToServer(readStartOffset,readStartOffset.length,CMD_ENCODE_SM);
                    }else if (TaskID==(byte) task_demog.READ_DATA.ordinal()){
                        //Log.d(TAG, "READ_DATA" );
                        System.arraycopy(rxdPacket, 0, readBuffComplete, OffsetRead-2, rxdPacket.length-4);
                        // //Log.d(TAG, "readBuffComplete: "+getHexString(readBuffComplete));
                        OffsetRead+=rxdPacket.length-4;
                        if (OffsetRead>=DemoGraphicSize){
                            String strDemoGraphicData = new String(readBuffComplete, StandardCharsets.UTF_8);
                            String[] strParsing = strDemoGraphicData.split("\",\"");
                            //Log.d(TAG, "strDemoGraphicData: "+strDemoGraphicData);
                            try {
                                JSONObject jsnDemog;
                                jsnDemog=new JSONObject();
                                jsnDemog.put("nik",strParsing[0].replace("\"",""));
                                jsnDemog.put("nama",strParsing[13]);
                                jsnDemog.put("tempat_lahir",strParsing[4]);
                                jsnDemog.put("tgl_lahir",strParsing[14]);
                                jsnDemog.put("alamat",strParsing[1]);
                                jsnDemog.put("rt_rw",strParsing[2]+"/"+strParsing[3]);
                                jsnDemog.put("propinsi",strParsing[15]);
                                jsnDemog.put("kabupaten",strParsing[7]);
                                jsnDemog.put("kecamatan",strParsing[5]);
                                jsnDemog.put("kelurahan",strParsing[6]);
                                jsnDemog.put("jkelamin",strParsing[8]);
                                jsnDemog.put("agama",strParsing[10]);
                                jsnDemog.put("status_perkawinan",strParsing[11]);
                                jsnDemog.put("pekerjaan",strParsing[12]);
                                jsnDemog.put("gol_darah",strParsing[9]);
                                jsnDemog.put("kewarganegaraan",strParsing[19]);
                                JSONObject finalJsnDemog = jsnDemog;
                                callbackListener.onReadDemographic(finalJsnDemog);
                            }catch (Exception e) {
                                Log.d(TAG, "Demog: " + e.getMessage());
                            }

                            if (strExtdata.equalsIgnoreCase("1")){
                                TaskID= (byte) task_demog.FINISH.ordinal();
                                sendFreeStatus();
                            }else if (strExtdata.equalsIgnoreCase("2")){
                                TaskID = (byte) task_demog.SELECT_EF_SIGNATURE.ordinal();
                                byte[] ActivateAutoDeciphering = atohex("00FA050000");
                                sendAuthToServer(ActivateAutoDeciphering, ActivateAutoDeciphering.length, CMD_START_SIGNATURE);
                            }
                        }else{
                            if ((OffsetRead + MaximumBuffer) > DemoGraphicSize){
                                readBuffer[2]=(byte)((OffsetRead >> 8) & 0xff);
                                readBuffer[3]=(byte)((OffsetRead >> 0) & 0xff);
                                readBuffer[4]=(byte)(DemoGraphicSize-OffsetRead+2);
                                ////Log.d(TAG, "readBuffDemoGraphic1: "+getHexString(readBuffDemoGraphic));
                                sendAuthToServer(readBuffer,(byte)readBuffer.length,CMD_ENCODE_SM);
                            }else{
                                readBuffer[2]=(byte)((OffsetRead >> 8) & 0xff);
                                readBuffer[3]=(byte)((OffsetRead >> 0) & 0xff);
                                readBuffer[4]=(byte)MaximumBuffer;
                                ////Log.d(TAG, "readBuffDemoGraphic2: "+getHexString(readBuffDemoGraphic));
                                sendAuthToServer(readBuffer,(byte)readBuffer.length,CMD_ENCODE_SM);
                            }
                        }
                    }else if (TaskID==(byte) task_demog.SELECT_EF_SIGNATURE.ordinal()){
                        //Log.d(TAG, "TaskID = SELECT_EF_SIGNATURE" );
                        TaskID= (byte) task_demog.READ_SIZE_SIGNATURE.ordinal();
                        byte[] ReadSizeCmd = atohex("00B0000008");
                        sendAuthToServer(ReadSizeCmd,ReadSizeCmd.length,CMD_ENCODE_SM);
                    }else if (TaskID==(byte) task_demog.READ_SIZE_SIGNATURE.ordinal()){
                        //Log.d(TAG, "TaskID = READ_SIZE_SIGNATURE" );
                        TaskID= (byte) task_demog.READ_DATA_SIGNATURE.ordinal();
                        SignatureSize=((rxdPacket[0] & 0xFF) << 8) |((rxdPacket[1] & 0xFF) << 0);
                        //Log.d(TAG,"Signature Size: "+SignatureSize);
                        SignatureComplete=new byte[SignatureSize];
                        System.arraycopy(rxdPacket, 2, SignatureComplete, 0, 6);
                        OffsetRead=8;
                        byte[] readStartOffset=atohex("00B00008D0");    //mulai dari offset 0x02, sebanyak 0xD0
                        readStartOffset[4]=(byte)MaximumBuffer;
                        sendAuthToServer(readStartOffset,readStartOffset.length,CMD_ENCODE_SM);
                    }else if (TaskID==(byte) task_demog.READ_DATA_SIGNATURE.ordinal()){
                        //Log.d(TAG, "TaskID = READ_DATA_SIGNATURE" );
                        try {
                            int selisih=0;
                            if (((OffsetRead - 2) + (rxdPacket.length - 4)) > SignatureSize){
                                //resize buffer
                                int Resize=((OffsetRead - 2) + (rxdPacket.length - 4));
                                //Log.d(TAG, "resize buffer: "+Resize);
                                selisih=Resize-SignatureSize;
                                //Log.d(TAG, "selisih: "+selisih);
                            }
                            System.arraycopy(rxdPacket, 0, SignatureComplete, OffsetRead - 2, (rxdPacket.length - 4 -selisih));

                            //Log.d(TAG, "SignatureComplete: "+getHexString(SignatureComplete));
                            OffsetRead += rxdPacket.length - 4;
                            //Log.d(TAG, "OffsetRead: " + OffsetRead);
                            if (OffsetRead >= SignatureSize) {
                                TaskID= (byte) task_demog.FINISH.ordinal();
                                if (!(SignatureComplete.equals(null))) {
                                    Bitmap ttdBm = decompressToImage(SignatureComplete, 168, 44);
                                    Bitmap ttdBmTrans = makeTransparentBitmap(ttdBm, 80);
                                    String base64Image=convertBitmapToBase64(ttdBmTrans);
                                    callbackListener.onReadSignature(base64Image);
                                }
                            } else {
                                if ((OffsetRead + MaximumBuffer) > SignatureSize) {
                                    readBuffer[2] = (byte) ((OffsetRead >> 8) & 0xff);
                                    readBuffer[3] = (byte) ((OffsetRead >> 0) & 0xff);
                                    int num = SignatureSize - OffsetRead;
                                    while (num % 8 != 0) {
                                        num += 1;
                                        //Log.d(TAG, "num: " + num);
                                    }
                                    readBuffer[4] = (byte) (num & 0xff);
                                    //Log.d(TAG, "ReadSignature_a: " + getHexString(readBuffer));
                                    sendAuthToServer(readBuffer, readBuffer.length, CMD_ENCODE_SM);
                                } else {
                                    readBuffer[2] = (byte) ((OffsetRead >> 8) & 0xff);
                                    readBuffer[3] = (byte) ((OffsetRead >> 0) & 0xff);
                                    readBuffer[4] = (byte) MaximumBuffer;
                                    //Log.d(TAG, "ReadSignature_b: " + getHexString(readBuffer));
                                    sendAuthToServer(readBuffer, readBuffer.length, CMD_ENCODE_SM);
                                }
                            }
                        }catch (Exception e) {
                            Log.d(TAG, "Sign: " + e.getMessage());

                        }
                    }else if (TaskID==(byte) task_demog.SELECT_EF_MINUTIAE1.ordinal()){
                        //Log.d(TAG, "TaskID = SELECT_EF_MINUTIAE1" );
                        TaskID= (byte) task_demog.READ_SIZE_MINUTIAE1.ordinal();
                        byte[] ReadSizeCmd = atohex("00B0000008");
                        sendAuthToServer(ReadSizeCmd,ReadSizeCmd.length,CMD_ENCODE_SM);
                    }else if (TaskID==(byte) task_demog.READ_SIZE_MINUTIAE1.ordinal()){
                        //Log.d(TAG, "TaskID = READ_SIZE_MINUTIAE1" );
                        TaskID= (byte) task_demog.READ_DATA_MINUTIAE1.ordinal();
                        Minutiae1Size=((rxdPacket[0] & 0xFF) << 8) |((rxdPacket[1] & 0xFF) << 0);
                        //Log.d(TAG,"MINUTIAE1 Size: "+Minutiae1Size);
                        Minutiae1Complete=new byte[Minutiae1Size];
                        System.arraycopy(rxdPacket, 2, Minutiae1Complete, 0, 6);
                        OffsetRead=8;
                        byte[] readStartOffset=atohex("00B00008D0");    //mulai dari offset 0x02, sebanyak 0xD0
                        readStartOffset[4]=(byte)MaximumBuffer;
                        sendAuthToServer(readStartOffset,readStartOffset.length,CMD_ENCODE_SM);
                    }
                }else {
                    sendFreeStatus();
                }
            }
        } catch (Exception e) {
            sendFreeStatus();
            Log.d(TAG, "Transaksi Exception:" +e.getMessage());
        }
        return -1;
    }

    private void setupSubscription(String topic) {
        mqttClient.subscribeWith()
                .topicFilter(topic)
                .qos(MqttQos.AT_LEAST_ONCE)
                .callback(publish -> {
                    String message = new String(publish.getPayloadAsBytes());
                    JSONObject jsnMsg = null;
                    try {
                        jsnMsg = new JSONObject(message);
                        if (topic.startsWith("ektp/hbeatres")) {
                            //Log.d(TAG,"hbeatres: "+jsnMsg);
                        }else if (topic.startsWith("ektp/findsamres")) {
                            if (jsnMsg.getString("rcode").equals("00")) {
                                if (jsnMsg.getInt("FlagFound") == 1) {
                                    strSamId = jsnMsg.getString("samid");
                                    sendAuthToServer(BuffToSam, LengthDataToSam, CommandToSam);
                                } else {
                                    callbackListener.onError("Sam not ready");
                                }
                            }else{
                                callbackListener.onError(jsnMsg.getString("message"));
                            }
                        }else if (topic.startsWith("ektp/authres")) {
                            if (jsnMsg.getString("rcode").equalsIgnoreCase("00")) {
                                //success
                                String strRxData = jsnMsg.getString("data");
                                byte byteRxData[] = HexStringToByteArray(strRxData);
                                //Log.d(TAG,"ektpauthres byteRxData: "+Util.DebugHexString(byteRxData));
                                int intCmd = Integer.parseInt(jsnMsg.getString("cmd").substring(0, 2), 16);
                                Transaksi(byteRxData, (byte) intCmd);
                            } else {
                                callbackListener.onError("RC=" + jsnMsg.getString("rcode") +", " + jsnMsg.getString("msg"));
                            }
                        }else if (topic.startsWith("ektp/demogdb")) {
                            TaskID= (byte) task_demog.FINISH.ordinal();
                            String strRxData = jsnMsg.getString("data");
                            byte byteRxData[] = HexStringToByteArray(strRxData);
                            byte byteRxDemog[] = new byte[byteRxData.length-2];
                            System.arraycopy(byteRxData, 2, byteRxDemog, 0, byteRxDemog.length);
                            String strDemoGraphicData = new String(byteRxDemog, StandardCharsets.UTF_8);
                            String[] strParsing = strDemoGraphicData.split("\",\"");
                            try {
                                JSONObject jsnDemog;
                                jsnDemog=new JSONObject();
                                jsnDemog.put("nik",strParsing[0].replace("\"",""));
                                jsnDemog.put("nama",strParsing[13]);
                                jsnDemog.put("tempat_lahir",strParsing[4]);
                                jsnDemog.put("tgl_lahir",strParsing[14]);
                                jsnDemog.put("alamat",strParsing[1]);
                                jsnDemog.put("rt_rw",strParsing[2]+"/"+strParsing[3]);
                                jsnDemog.put("propinsi",strParsing[15]);
                                jsnDemog.put("kabupaten",strParsing[7]);
                                jsnDemog.put("kecamatan",strParsing[5]);
                                jsnDemog.put("kelurahan",strParsing[6]);
                                jsnDemog.put("jkelamin",strParsing[8]);
                                jsnDemog.put("agama",strParsing[10]);
                                jsnDemog.put("status_perkawinan",strParsing[11]);
                                jsnDemog.put("pekerjaan",strParsing[12]);
                                jsnDemog.put("gol_darah",strParsing[9]);
                                jsnDemog.put("kewarganegaraan",strParsing[19]);
                                JSONObject finalJsnDemog = jsnDemog;
                                //new Handler(Looper.getMainLooper()).post(() -> callbackListener.onReadDemographic(finalJsnDemog));
                                callbackListener.onReadDemographic(finalJsnDemog);
                                sendFreeStatus();
                            }catch (Exception e) {
                                Log.d(TAG, "Demog: " + e.getMessage());
                            }
                            sendFreeStatus();
                        }
                    } catch (JSONException e) {
                        throw new RuntimeException(e);
                    }
                })
                .send()
                .whenComplete((subAck, throwable) -> {
                    if (throwable != null) {
                        Log.e(TAG, "Failed to subscribe", throwable);
                    } else {
                        Log.d(TAG, "Subscribed: " + topic);
                    }
                });
    }

    private void publish(String topic, String message) {
        if (isConnected) {
            mqttClient.publishWith()
                    .topic(topic)
                    .payload(message.getBytes())
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .send()
                    .whenComplete((publish, throwable) -> {
                        if (throwable != null) {
                            Log.e(TAG, "Failed to publish", throwable);
                        }
                    });
        } else {
            Log.e(TAG, "Not connected, cannot publish");
        }
    }

    private void startPeriodicPublish() {
        periodicPublishRunnable = new Runnable() {
            @Override
            public void run() {
                if (isConnected) {
                    if (cntSecond++>30) {
                        cntSecond=0;
                        sendPing("hbeat");
                    }
                    handler.postDelayed(this, 1000);
                }
            }
        };
        handler.postDelayed(periodicPublishRunnable, 1000);
    }

    public void stopPeriodicPublish() {
        handler.removeCallbacks(periodicPublishRunnable);
    }



    public boolean isConnected() {
        return isConnected;
    }

    public void handleNewIntent(Intent intent) {
        byte[] id = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);

        try {
            if (id.length>4) {
                byteUID = new byte[8];
                byteUID[0] = (byte) 0x80;
                System.arraycopy(id, 0, byteUID, 1, 7);
            }
            // Log.d(TAG, "byteUID: " + utilclass.getHexStringFromByteArray(byteUID));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //ctx.setIntent(intent);
        String actionIntent = intent.getAction();
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(actionIntent) || NfcAdapter.ACTION_TECH_DISCOVERED.equals(actionIntent) || NfcAdapter.ACTION_NDEF_DISCOVERED.equals(actionIntent)) {
            Parcelable parcelTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            //Log.d(TAG, "parcelTag: "+parcelTag.toString());
            Tag tag = (Tag) parcelTag;
            handleNfcIntent(tag,byteUID);
        }
    }

    public void close() {
        stopPeriodicPublish();
        if (isConnected) {
            mqttClient.disconnect();
            isConnected = false;
        }
    }

    /*
    if (callbackListener != null) {
        callbackListener.onMessageReceived(topic, message);
    }

    byte[] finalRespAPDU = respAPDU;
    new Handler(Looper.getMainLooper()).post(() -> callbackListener.onTagRead(finalRespAPDU));
    */
    public interface KtpListener {
        void onMessageReceived(String topic, String message);
        void onReadPhoto(String dataPhotoBase64);
        void onReadDemographic(JSONObject jsnDemographic);
        void onReadSignature(String dataSignatureBase64);
        void onError(String strError);
    }


}