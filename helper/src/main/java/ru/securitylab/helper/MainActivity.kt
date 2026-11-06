package ru.securitylab.helper
import android.app.Activity
import android.content.Intent
import android.media.projection.MediaProjectionConfig
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import org.json.JSONObject
import ru.securitylab.common.Evidence
import ru.securitylab.common.Screen

class MainActivity:Activity(){
 private var token="manual"
 override fun onCreate(state:Bundle?){super.onCreate(state);dispatch(intent)}
 override fun onNewIntent(i:Intent){super.onNewIntent(i);setIntent(i);dispatch(i)}
 private fun dispatch(i:Intent){
  token=i.getStringExtra("token")?:"manual"
  try{when(val op=i.getStringExtra("op")?:"home"){
   "overlay"->{check(Settings.canDrawOverlays(this)){"Overlay permission missing"};startForegroundService(Intent(this,OverlayService::class.java).putExtra("token",token));finish()}
   "overlay_stop"->{stopService(Intent(this,OverlayService::class.java));Evidence.emit(this,token,op,JSONObject().put("requested",true));finish()}
   "capture_start"->startActivityForResult(getSystemService(MediaProjectionManager::class.java).createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay()),81)
   "snapshot","reuse","capture_stop"->{startService(Intent(this,CaptureService::class.java).setAction(op).putExtra("token",token));finish()}
   else->Screen(this,"Lab Helper","Чужое окно и настоящий захват экрана").apply{
    button("Разрешить наложения"){startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,Uri.parse("package:$packageName")))}
    button("Показать наложение"){dispatch(Intent().putExtra("op","overlay"))}
    button("Убрать наложение"){dispatch(Intent().putExtra("op","overlay_stop"))}
    button("Начать захват экрана"){dispatch(Intent().putExtra("op","capture_start"))}
    button("Сохранить кадр"){dispatch(Intent().putExtra("op","snapshot"))}
    button("Повторно использовать согласие"){dispatch(Intent().putExtra("op","reuse"))}
    button("Остановить захват"){dispatch(Intent().putExtra("op","capture_stop"))}
   }
  }}catch(e:Exception){Evidence.emit(this,token,i.getStringExtra("op")?:"error",Evidence.error(e).put("operation_error",true))}
 }
 @Deprecated("Platform projection consent") override fun onActivityResult(request:Int,result:Int,data:Intent?){
  super.onActivityResult(request,result,data)
  if(request!=81)return
  if(result==RESULT_OK&&data!=null)startForegroundService(Intent(this,CaptureService::class.java).setAction("start").putExtra("token",token).putExtra("code",result).putExtra("consent",data))
  else Evidence.emit(this,token,"capture_start",JSONObject().put("consented",false))
  finish()
 }
}
