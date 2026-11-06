package ru.securitylab.sample
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import org.json.JSONObject
import ru.securitylab.common.Evidence
import ru.securitylab.common.Screen
import java.util.UUID
class MainActivity:Activity(){
 override fun onCreate(b:Bundle?){super.onCreate(b);show(intent)}
 override fun onNewIntent(i:Intent){super.onNewIntent(i);show(i)}
 private fun show(i:Intent){
  val p=getSharedPreferences("record",MODE_PRIVATE)
  if(!p.contains("note"))p.edit().putString("note","Запись "+UUID.randomUUID()).commit()
  val note=p.getString("note","")!!
  Screen(this,"Update Sample","Установленная версия: ${BuildConfig.VERSION_CODE}").apply{
   card(note);text("При корректном обновлении запись сохраняется. Несовместимая подпись не должна заменить приложение.")
  }
  Evidence.emit(this,i.getStringExtra("token")?:"manual","sample_state",JSONObject().put("version",BuildConfig.VERSION_CODE).put("note",note).put("note_sha256",Evidence.sha(note.toByteArray())))
 }
}
