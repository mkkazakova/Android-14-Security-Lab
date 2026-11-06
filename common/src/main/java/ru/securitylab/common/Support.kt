package ru.securitylab.common

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Process
import android.os.SystemClock
import android.util.Log
import android.view.View
import android.widget.*
import org.json.JSONObject
import java.io.File

object Evidence {
    @Synchronized fun emit(context: Context, token: String, op: String, data: JSONObject): JSONObject {
        val record = JSONObject().put("token",token).put("operation",op)
            .put("package",context.packageName).put("uid",Process.myUid())
            .put("elapsed_ms",SystemClock.elapsedRealtime()).put("timestamp_ms",System.currentTimeMillis()).put("data",data)
        val dir=context.createDeviceProtectedStorageContext().filesDir
        File(dir,"events.jsonl").appendText(record.toString()+"\n")
        val encoded=android.util.Base64.encodeToString(record.toString().toByteArray(Charsets.UTF_8),android.util.Base64.NO_WRAP)
        val pieces=encoded.chunked(2800)
        pieces.forEachIndexed{index,part->Log.i("ASL","ASL_CHUNK:$token:$op:$index:${pieces.size}:$part")}
        return record
    }
    fun error(e: Throwable): JSONObject = JSONObject().put("exception",e.javaClass.name)
        .put("message",e.message).put("stack",Log.getStackTraceString(e).take(1800))
        .put("causes",generateSequence(e as Throwable?){it.cause}.take(8).joinToString(" | "){it.javaClass.name+": "+it.message}.take(800))
    fun sha(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

class Screen(val activity: Activity, title: String, subtitle: String) {
    val body=LinearLayout(activity).apply {
        orientation=LinearLayout.VERTICAL;setPadding(24,24,24,32);setBackgroundColor(Color.rgb(243,246,250))
    }
    init {
        activity.setContentView(ScrollView(activity).apply { addView(body) })
        text("ANDROID SECURITY LAB",12,Color.rgb(22,125,141))
        text(title,26,Color.rgb(24,39,58),true);text(subtitle,15)
    }
    fun text(value:String,size:Int=17,color:Int=Color.rgb(68,83,101),bold:Boolean=false):TextView {
        val v=TextView(activity).apply { text=value;textSize=size.toFloat();setTextColor(color);setPadding(0,8,0,14);if(bold)setTypeface(null,Typeface.BOLD) }
        body.addView(v);return v
    }
    fun button(label:String, action:()->Unit):Button {
        val v=Button(activity).apply { text=label;isAllCaps=false;setOnClickListener { action() } }
        body.addView(v,LinearLayout.LayoutParams(-1,-2).apply { bottomMargin=10 });return v
    }
    fun edit(hint:String,value:String=""):EditText {
        val v=EditText(activity).apply { this.hint=hint;setText(value);textSize=17f }
        body.addView(v);return v
    }
    fun card(value:String):TextView = text(value,19,Color.rgb(24,39,58)).apply {
        setPadding(20,20,20,20);background=GradientDrawable().apply{setColor(Color.WHITE);cornerRadius=18f}
    }
}
