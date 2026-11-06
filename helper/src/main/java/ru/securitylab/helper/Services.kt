package ru.securitylab.helper
import android.app.*
import android.content.Intent
import android.graphics.*
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.*
import android.view.*
import android.widget.TextView
import org.json.JSONObject
import ru.securitylab.common.Evidence
import java.io.File
import java.util.UUID

fun Service.foreground(id:Int,title:String){
 val nm=getSystemService(NotificationManager::class.java)
 nm.createNotificationChannel(NotificationChannel("lab","Лабораторные операции",NotificationManager.IMPORTANCE_LOW))
 startForeground(id,Notification.Builder(this,"lab").setSmallIcon(android.R.drawable.ic_menu_view).setContentTitle(title).setContentText("Security Lab · тестовая операция").build())
}
class OverlayService:Service(){
  private val overlays=mutableListOf<View>()
  private val layerAlpha=0.65f
  override fun onBind(i:Intent?)=null
  private fun removeAllOverlays(){
    val wm=getSystemService(WindowManager::class.java)
    overlays.forEach { runCatching { wm.removeView(it) } }
    overlays.clear()
  }
  override fun onStartCommand(i:Intent?,flags:Int,id:Int):Int{
    foreground(11,"Наложения другого приложения")
    val token=i?.getStringExtra("token")?:"manual"
    try{
      if(overlays.isEmpty()){
        val wm=getSystemService(WindowManager::class.java)
        repeat(2){ layer->
          val v=TextView(this).apply{
            text=if(layer==1)"LAB HELPER · ДВА ЧУЖИХ ОКНА\nКаждое окно пропускает касания · alpha 0.65" else ""
            textSize=20f
            setTextColor(Color.BLACK)
            gravity=Gravity.CENTER
            setBackgroundColor(Color.CYAN)
          }
          val p=WindowManager.LayoutParams(-1,-1,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
              WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
              WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT).apply{
              alpha=layerAlpha
              gravity=Gravity.TOP or Gravity.START
            }
          wm.addView(v,p)
          overlays.add(v)
        }
      }
      val combined=1f-(1f-layerAlpha)*(1f-layerAlpha)
      Evidence.emit(this,token,"overlay",JSONObject()
        .put("shown",overlays.size==2)
        .put("layers",overlays.size)
        .put("alpha",layerAlpha.toDouble())
        .put("combined_alpha",combined.toDouble())
        .put("not_touchable",true)
        .put("type",WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY))
    }catch(e:Exception){
      Evidence.emit(this,token,"overlay",Evidence.error(e).put("operation_error",true))
      removeAllOverlays()
      stopSelf()
    }
    return START_NOT_STICKY
  }
  override fun onDestroy(){removeAllOverlays();super.onDestroy()}
}
class CaptureService:Service(){
 private var projection:MediaProjection?=null
 private var display:VirtualDisplay?=null
 private var reader:ImageReader?=null
 private val thread=HandlerThread("capture").apply{start()}
 private val handler=Handler(thread.looper)
 @Volatile private var pending:String?=null
 private var frames=0L
 private var startToken="manual"
 private var width=0;private var height=0
 override fun onBind(i:Intent?)=null
 override fun onStartCommand(i:Intent?,flags:Int,id:Int):Int{
  val token=i?.getStringExtra("token")?:"manual"
  try{when(i?.action){
   "start"->{
    startToken=token;foreground(12,"Захват экрана разрешён Android")
    val consent=i.getParcelableExtra("consent",Intent::class.java)?:error("Missing consent")
    projection=getSystemService(MediaProjectionManager::class.java).getMediaProjection(i.getIntExtra("code",0),consent)
    projection!!.registerCallback(object:MediaProjection.Callback(){override fun onStop(){Evidence.emit(this@CaptureService,startToken,"projection_stopped",JSONObject().put("frames",frames));display?.release();display=null}},handler)
    val bounds=getSystemService(WindowManager::class.java).maximumWindowMetrics.bounds;width=bounds.width();height=bounds.height()
    reader=ImageReader.newInstance(width,height,PixelFormat.RGBA_8888,3)
    reader!!.setOnImageAvailableListener({r->
     val frame=r.acquireLatestImage()?:return@setOnImageAvailableListener
     val captureToken=pending
     try{
      frames++
      val t=captureToken
      if(t!=null){
       pending=null
       val plane=frame.planes[0];val padded=plane.rowStride/plane.pixelStride
       val full=Bitmap.createBitmap(padded,height,Bitmap.Config.ARGB_8888);full.copyPixelsFromBuffer(plane.buffer)
       val bitmap=Bitmap.createBitmap(full,0,0,width,height)
       val file=File(filesDir,"capture-${UUID.randomUUID()}.png")
       file.outputStream().use{bitmap.compress(Bitmap.CompressFormat.PNG,100,it)}
       Evidence.emit(this,t,"snapshot",JSONObject().put("file",file.name).put("width",width).put("height",height).put("frame",frames).put("sha256",Evidence.sha(file.readBytes())))
       bitmap.recycle();if(bitmap!==full)full.recycle()
      }
     }catch(e:Exception){Evidence.emit(this,captureToken?:token,"snapshot",Evidence.error(e).put("operation_error",true))}finally{frame.close()}
    },handler)
    display=projection!!.createVirtualDisplay("ASL",width,height,resources.displayMetrics.densityDpi,DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,reader!!.surface,null,handler)
    Evidence.emit(this,token,"capture_start",JSONObject().put("consented",true).put("display_created",display!=null).put("width",width).put("height",height))
   }
   "snapshot"->{check(display!=null){"No active projection"};handler.postDelayed({pending=token},1500)}
   "reuse"->{
    check(display!=null&&projection!=null){"No active projection"}
    try{val second=projection!!.createVirtualDisplay("ASL-second",width,height,resources.displayMetrics.densityDpi,DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,reader!!.surface,null,handler);second.release();Evidence.emit(this,token,"reuse",JSONObject().put("accepted",true))}
    catch(e:Exception){Evidence.emit(this,token,"reuse",Evidence.error(e).put("accepted",false))}
   }
   "capture_stop"->{projection?.stop();stopSelf();Evidence.emit(this,token,"capture_stop",JSONObject().put("requested",true))}
  }}catch(e:Exception){Evidence.emit(this,token,if(i?.action=="start")"capture_start" else i?.action?:"capture_error",Evidence.error(e).put("operation_error",true))}
  return START_NOT_STICKY
 }
 override fun onDestroy(){projection?.stop();display?.release();reader?.close();thread.quitSafely();super.onDestroy()}
}
