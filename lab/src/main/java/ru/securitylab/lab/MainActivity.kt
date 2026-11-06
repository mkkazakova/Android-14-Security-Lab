package ru.securitylab.lab

import android.app.Activity
import android.app.KeyguardManager
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import ru.securitylab.common.Evidence
import ru.securitylab.common.Screen
import java.net.URL
import javax.net.ssl.HttpsURLConnection

class MainActivity:Activity(){
    private var token="manual"
    private var authToken="manual"
    private var tapCount=0
    private var touchCount=0
    private var current="home"
    private var tapLabel:TextView?=null
    override fun onCreate(state:Bundle?){super.onCreate(state);dispatch(intent)}
    override fun onNewIntent(i:Intent){super.onNewIntent(i);setIntent(i);dispatch(i)}
    private fun emit(op:String,data:JSONObject,t:String=token)=Evidence.emit(this,t,op,data)
    private fun dispatch(i:Intent){
        token=i.getStringExtra("token")?:"manual"
        val op=i.getStringExtra("op")?:"home"
        try { when(op){
            "home"->home()
            "boot_prepare"->{val result=BootData.prepare(this,token);bootScreen();emit(op,result)}
            "boot_probe"->{val r=BootData.probe(this,i.getStringExtra("stage")?:"manual");bootScreen();emit(op,r)}
            "boot_history"->{bootScreen();emit(op,JSONObject().put("history",BootData.history(this)))}
            "key_create"->{val r=KeyVault.create(this);vaultScreen("Ключ создан. Подтвердите PIN для сохранения записи.");emit(op,r)}
            "key_try"->{val r=KeyVault.attempt(this);vaultScreen(if(r.optBoolean("decrypted"))r.optString("plaintext") else "Android не разрешил расшифрование: "+r.optString("exception"));emit(op,r)}
            "key_auth"->authenticate()
            "tap"->{tapCount=0;touchCount=0;tapScreen();emit(op,JSONObject().put("ready",true))}
            "tap_state"->{emit(op,JSONObject().put("clicks",tapCount).put("saved_count",getSharedPreferences("tap",MODE_PRIVATE).getInt("count",0)).put("touches",touchCount).put("screen",current))}
            "hide_overlay"->{window.setHideOverlayWindows(i.getBooleanExtra("enabled",true));emit(op,JSONObject().put("enabled",i.getBooleanExtra("enabled",true)))}
            "capture"->{captureScreen(i.getBooleanExtra("secure",false));emit(op,JSONObject().put("secure",window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE !=0))}
            "tls"->network(i.getStringExtra("url")?:"https://10.0.2.2:8443/")
            else->error("Unknown operation: $op")
        }}catch(e:Exception){emit(op,Evidence.error(e).put("operation_error",true));Screen(this,"Операция не выполнена",op).card(e.javaClass.simpleName+": "+e.message)}
    }
    private fun home(){
        current="home";window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);window.setHideOverlayWindows(false)
        Screen(this,"Безопасность Android","Шесть реальных экспериментов · Android 14").apply{
            button("01 · Данные до разблокировки"){bootScreen()}
            button("02 · Запись под защитой PIN"){vaultScreen("Ключ и зашифрованная запись")}
            button("03 · Подпись обновления"){Screen(this@MainActivity,"Обновление приложения","Откройте Update Sample. Три APK и точные команды установки находятся в отчёте и README.").button("Назад"){home()}}
            button("04 · Наложения и касания"){tapCount=0;touchCount=0;tapScreen()}
            button("05 · Доверие к серверу"){networkScreen()}
            button("06 · Защита экрана"){captureScreen(false)}
        }
    }
    private fun bootScreen(){
        current="boot"
        Screen(this,"Данные и первая разблокировка","DE доступно до ввода PIN; CE проверяется после настоящей перезагрузки.").apply{
            button("Подготовить две записи"){dispatch(Intent().putExtra("op","boot_prepare"))}
            button("Проверить доступ сейчас"){dispatch(Intent().putExtra("op","boot_probe"))}
            val h=BootData.history(this@MainActivity)
            for(n in 0 until h.length()){
                val r=h.getJSONObject(n)
                card("${r.optString("stage")} · загрузка ${r.optInt("boot_count")}\nDE: ${r.getJSONObject("de").optBoolean("read")} · CE: ${r.getJSONObject("ce").optBoolean("read")}\nПользователь разблокирован: ${r.optBoolean("unlocked")}")
            };button("Каталог"){home()}
        }
    }
    private fun vaultScreen(message:String){
        current="vault";window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        Screen(this,"Защищённая запись","Android Keystore · доступ после системного PIN на 30 секунд").apply{
            card(message)
            button("Создать новый ключ"){dispatch(Intent().putExtra("op","key_create"))}
            button("Подтвердить PIN и открыть запись"){authenticate()}
            button("Попытаться расшифровать без запроса"){dispatch(Intent().putExtra("op","key_try"))}
            button("Каталог"){home()}
        }
    }
    @Suppress("DEPRECATION") private fun authenticate(){
        authToken=token
        val km=getSystemService(KeyguardManager::class.java)
        val request=km.createConfirmDeviceCredentialIntent("Открыть защищённую запись","PIN проверяет Android. Приложение его не получает.")?:error("Secure PIN is not configured")
        startActivityForResult(request,700)
    }
    @Deprecated("Platform credential confirmation") override fun onActivityResult(request:Int,result:Int,data:Intent?){
        super.onActivityResult(request,result,data)
        if(request!=700)return
        val r=if(result==RESULT_OK)try{if(KeyVault.hasData(this))KeyVault.decrypt(this) else KeyVault.seed(this)}catch(e:Exception){Evidence.error(e).put("decrypted",false)}
            else JSONObject().put("decrypted",false)
        r.put("authenticated",result==RESULT_OK)
        vaultScreen(if(r.optBoolean("decrypted"))r.optString("plaintext") else "Запись не открыта. "+r.optString("exception"))
        emit("key_auth",r,authToken)
    }
    private fun tapScreen(){
        current="tap";window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        Screen(this,"Защищаемое действие","Lab Helper может поместить чужое окно поверх этой кнопки.").apply{
            tapLabel=card("Сохранено записей: $tapCount")
            button("СОХРАНИТЬ ТЕСТОВУЮ ЗАПИСЬ"){
                val next=tapCount+1
                check(getSharedPreferences("tap",MODE_PRIVATE).edit().putInt("count",next).putLong("saved_at",System.currentTimeMillis()).commit()){ "Cannot persist the test record" }
                tapCount=next
                tapLabel?.text="Сохранено записей: $tapCount"
            }.apply{contentDescription="tap-target";minHeight=180}
            button("Скрыть чужие наложения"){window.setHideOverlayWindows(true)}
            button("Разрешить показ наложений"){window.setHideOverlayWindows(false)}
            button("Каталог"){home()}
        }
    }
    override fun dispatchTouchEvent(e:MotionEvent):Boolean{
        if(current=="tap"&&e.action==MotionEvent.ACTION_DOWN){touchCount++;emit("touch",JSONObject().put("flags",e.flags).put("x",e.x).put("y",e.y))}
        return super.dispatchTouchEvent(e)
    }
    private fun captureScreen(secure:Boolean){
        current="capture"
        if(secure)window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        Screen(this,"Запись на экране","Запустите захват в Lab Helper. Защита действует на захваты Android, а не на внешнюю камеру.").apply{
            card("ТЕСТОВЫЕ ДАННЫЕ · 4827\n"+if(secure)"FLAG_SECURE включён" else "Обычное окно")
            val clock=text("Кадр")
            val ticker=android.os.Handler(mainLooper)
            val tick=object:Runnable{override fun run(){if(current=="capture" && clock.isAttachedToWindow){clock.text="Время кадра: "+android.os.SystemClock.elapsedRealtime();ticker.postDelayed(this,200)}}}
            ticker.postDelayed(tick,300)
            body.addView(View(this@MainActivity).apply{setBackgroundColor(Color.MAGENTA)},LinearLayout.LayoutParams(-1,240))
            button("Включить защиту"){captureScreen(true)}
            button("Отключить защиту"){captureScreen(false)}
            button("Каталог"){home()}
        }
    }
    private fun networkScreen(){
        current="network"
        Screen(this,"Сетевое доверие","Локальный сервер должен быть запущен скриптом проекта.").apply{
            button("Доверенный TLS"){network("https://10.0.2.2:8443/")}
            button("Чужой центр сертификации"){network("https://10.0.2.2:8444/")}
            button("Неправильное имя сервера"){network("https://10.0.2.2:8445/")}
            button("Открытый HTTP"){network("http://10.0.2.2:8080/")}
            button("Каталог"){home()}
        }
    }
    private fun network(address:String){
        val t=token;val screen=Screen(this,"Соединение с сервером",address);val view=screen.card("Выполняется настоящий запрос…")
        Thread{
            val r=try{
                val connection=URL(address).openConnection() as java.net.HttpURLConnection
                connection.connectTimeout=6000;connection.readTimeout=6000;connection.instanceFollowRedirects=false
                try{
                    val code=connection.responseCode;val text=connection.inputStream.bufferedReader().use{it.readText()}
                    JSONObject().put("received",true).put("code",code).put("body",text).apply{
                        if(connection is HttpsURLConnection){put("cipher_suite",connection.cipherSuite);put("certificate_sha256",Evidence.sha(connection.serverCertificates[0].encoded))}
                    }
                }finally{connection.disconnect()}
            }catch(e:Exception){Evidence.error(e).put("received",false)}
            r.put("url",address)
            runOnUiThread{
                view.text=if(r.optBoolean("received"))r.optString("body") else "Соединение не установлено\n"+r.optString("exception")+"\n"+r.optString("message")
                screen.button("Другой запрос"){networkScreen()};emit("tls",r,t)
            }
        }.start()
    }
}
