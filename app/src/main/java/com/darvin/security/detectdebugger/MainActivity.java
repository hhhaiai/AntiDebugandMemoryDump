package com.darvin.security.detectdebugger;

import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    check_fs("/proc/net/tcp6");
                }catch (Throwable e){
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public native void check_fs(String path);
}
