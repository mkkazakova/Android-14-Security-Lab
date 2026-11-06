package ru.securitylab.lab

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import ru.securitylab.common.Evidence
import java.io.File
import java.util.UUID

object BootData {
    fun prefs(c:Context)=c.createDeviceProtectedStorageContext().getSharedPreferences("boot",Context.MODE_PRIVATE)
    fun prepare(c:Context, token:String):JSONObject {
        val de=("DE:"+UUID.randomUUID()).toByteArray();val ce=("CE:"+UUID.randomUUID()).toByteArray()
        File(c.createDeviceProtectedStorageContext().filesDir,"de.txt").writeBytes(de)
        File(c.filesDir,"ce.txt").writeBytes(ce)
        prefs(c).edit().putString("token",token).putString("history","[]")
            .putString("de_hash",Evidence.sha(de)).putString("ce_hash",Evidence.sha(ce)).commit()
        return probe(c,"prepared")
    }
    fun probe(c:Context, stage:String):JSONObject {
        val p=prefs(c)
        fun read(device:Boolean):JSONObject=try {
            val ctx=if(device)c.createDeviceProtectedStorageContext() else c.applicationContext
            val bytes=File(ctx.filesDir,if(device)"de.txt" else "ce.txt").readBytes()
            JSONObject().put("read",true).put("sha256",Evidence.sha(bytes))
                .put("matches",Evidence.sha(bytes)==p.getString(if(device)"de_hash" else "ce_hash",null))
        } catch(e:Exception){Evidence.error(e).put("read",false)}
        val result=JSONObject().put("stage",stage).put("unlocked",c.getSystemService(UserManager::class.java).isUserUnlocked)
            .put("boot_count",Settings.Global.getInt(c.contentResolver,Settings.Global.BOOT_COUNT,-1))
            .put("de",read(true)).put("ce",read(false)).put("elapsed_ms",android.os.SystemClock.elapsedRealtime())
        val history=JSONArray(p.getString("history","[]"));history.put(result)
        p.edit().putString("history",history.toString()).commit()
        return result
    }
    fun history(c:Context)=JSONArray(prefs(c).getString("history","[]"))
}
class BootProbe:BroadcastReceiver(){
    override fun onReceive(c:Context,intent:Intent){
        val p=BootData.prefs(c);val token=p.getString("token",null)?:return
        val stage=if(intent.action==Intent.ACTION_LOCKED_BOOT_COMPLETED)"locked_boot" else "boot_completed"
        try {Evidence.emit(c,token,"boot_receiver",BootData.probe(c,stage))}
        catch(e:Exception){Evidence.emit(c,token,"boot_receiver_error",Evidence.error(e))}
    }
}
