package ru.securitylab.helper
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import ru.securitylab.common.Evidence
/** Laboratory control only: commands target an already-running foreground projection service. */
class CommandReceiver:BroadcastReceiver(){
 override fun onReceive(context:Context,intent:Intent){
  val op=intent.getStringExtra("op")?:return
  if(op !in setOf("snapshot","reuse","capture_stop"))return
  val token=intent.getStringExtra("token")?:"manual"
  try{context.startService(Intent(context,CaptureService::class.java).setAction(op).putExtra("token",token))}
  catch(e:Exception){Evidence.emit(context,token,op,Evidence.error(e).put("operation_error",true))}
 }
}
