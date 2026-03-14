




// ----- utils.js START -----
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js";
import { getDatabase ,ref, push,  get, set, onChildAdded, remove, onChildRemoved }
from "https://www.gstatic.com/firebasejs/11.1.0/firebase-database.js";
import { getAuth,signInWithPopup, getRedirectResult,signInWithRedirect,GoogleAuthProvider,onAuthStateChanged,signOut,}
from "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js";

import { getFirestore, doc, getDoc,setDoc } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-firestore.js";
import { constructor } from "firebase";
//firesotreのモジュールをインポート

// Turf.js をESM形式で読み込む（URL形式）
import * as turf from 'https://cdn.skypack.dev/@turf/turf';


const REDIRECT_OPTIONS              = [true,false] as const
type RedirectOptions                = typeof REDIRECT_OPTIONS[number];
type LoginSystemArguments           = {
                                        HTML_BTN_ELEMENT : HTMLButtonElement
                                        SPAN_NAME        : HTMLSpanElement
                                        isRedirect       : RedirectOptions
                                        REDIRECT_METHOD? : "toSelectedPage"|"toHP";
                                        CALL_FROM?       : string
                                        QUERY?           : string
                                      }
type AuthDataType                   = {
                                        isLogined   : boolean
                                        accountData : any;
                                      }
const RENDER_AUTH_METHOD_OPTIONS    = ["signInWithPopup","onAuthStateChanged","signInWithRedirect"] as const;
type  RenderAuthMehodOptions        = typeof RENDER_AUTH_METHOD_OPTIONS[number];
type  RenderAuthType                = {
                                        HTML_BTN_ELEMENT    : HTMLButtonElement
                                        SPAN_NAME           : HTMLSpanElement
                                        METHOD              : RenderAuthMehodOptions
                                      }
/**
 * @description version 1.0.0では匿名でのログイン認証を行っていました。
 * version 2.0.0ではGoogleによるログイン認証を導入しました。
 * これにより、realtimebaseのデータパスを 【data/キーワード】から【GoogleUserID/キーワード】としました。
 * こちらのコードはversion 1.0.0と互換性がありません。version 1.0.0を使用している
 * 年賀状、匿名調整君、X_Linktreeでは昔のコードのままお使いください。
 * @version 3.3.0
 * @abstract
 * ```js
 * version 1.0.0　匿名認証機能で実装
 * version 2.0.0  GoogDE
 *           1.0  redirect関数の追加
 *           2.0  内部関数を#で隠しました
 *           2.1  #__logined関数をpromise返すように編集
 *           3.0  prepareUniqueID関数を導入
 *           4.0  UIDをもとに、ログイン状態を返すisLogined関数（外部用）を導入
 *            .1  UIDがログイン・ログアウト時に更新されなかったバグを修正
 *           5.0  #__loginWithGoogleとrenderAuthStatusにおいて、Google認証データをthis.ACCOUNT_DATA
 *                に保存するように仕様を変更
 * 　　　　　　　　 #__logoutFromGoogleでは、ログアウト時にthis.ACCOUNT_DATAを空にするようにしました。
 *           6.0  暗号化・解読関数 encryptDataとdecryptDataを導入
 *           7.0  暗号化encryptData関数の仕様を変更。IVとSALTはthisに保存することにした。
 *            .1  passwordを入れると暗号化時にpassword=undefindedになったり、解読時にpasswordが入ってしまう等の
 *              　バグで服同化が失敗するバグを修正
 *            .2  downloadメソッド実行時、インターネットの不調でうまくデータ取得できないときに５回までは再試行するように変更
 *           8.0  isEncryptedString関数を実装。encryptoDataで生成された暗号文か推測します。
 *           9.9  deleteData関数を導入。これで、realtime databaseeのデータを削除できます
 * version 3.0.0  GoogleAPIが使用できるように環境構築
 *                ・GoogleAPI仕様に向けてrenderAuthStatus, #__loginWithGoogle, #__logoutFromGoogleが認証結果に応じてbooleanを返すようにしました。
 *                ・renderAuthStatusに３つのオプションを追加。（redirectは未完成）
 *                ・renderAuthStatusにおいて、this.ACCESS_TOKENにAPI用のアクセストークンを保存するようにしました。
 *           1.0  firestoreからデータを取得するdownloadKeyFromFireStore関数を導入
 *           2.0  realtime databaseのファイルを消去するdeleteData関数を導入
 *            .1  ログイン必須時とログイン不要時のuploadData,downloadDataの使い方が分かりにくかったので、isLoginRequiredをクラス第二引数に明示しました。
 * 　　　　　　　　これは、可読性の向上であり今のところ、isLoginRequred=true, falseどちらも同じ挙動をします。
 *           3.9  deleteData関数を追加しました。

 * ```
 */
class FirebaseFunctions{
    DB                  : any;
    FIRESTORE_DB        : any;
    isShowTip           : {[key : string] : boolean} = {};
    PROVIDER            : any;
    AUTH                : any;
    UID                 : string;
    ACCOUNT_DATA        : any;//Google認証後にデータを格納します。
                              //renderAuthStatus内、#__isLoginedで使われているonAuthStateChangedでは
                              //result.userのデータのみ取得できる。さて、ページを閉じても認証状態は残る
                              //そんな時、this.ACCOUNT_DATAには２パターンのobjectが存在する可能性がある。
                              //UserCredentialImpl直下の全てのデータが入っているobjectか
                              //UserCredentialImpl￥userのデータのみか。
                              //これは潜在的なバグになる。そのため、this.ACCOUNT_DATAにはあらかじめuser直下のデータだけ
                              //保存する。
    ACCESS_TOKEN        : string;

    IV                  : Uint8Array;
    SALT                : Uint8Array;

    UtilsFunc           : UtilsFunctions;
    preloader           : PreLoader;

    IS_LOGIN_REQUIRED   : boolean;

    constructor(FIREBASE_CONFIG: object, IS_LOGIN_REQUIRED: boolean){
        // Initialize Firebase
        const APP           = initializeApp(FIREBASE_CONFIG);
        this.FIRESTORE_DB   = getFirestore(APP);
        this.DB             = getDatabase(APP);
        this.PROVIDER       = new GoogleAuthProvider();
        this.AUTH           = getAuth();
        this.UID            = ""; //GoogleAccountに紐づく固有ユーザーID
        this.ACCOUNT_DATA   = {};
        this.ACCESS_TOKEN   = "";

        this.IV             = crypto.getRandomValues(new Uint8Array(12));
        this.SALT           = crypto.getRandomValues(new Uint8Array(16));
        //この二つのattributeはencryptDataで使います。
        //firebaseにデータをセーブするとき、データの複数個所に別途PASSWORDを掛けたい場合があります
        //例：TaskManagerでデータ全体・タイトル・内容にencryptData処理をしたい
        //この時IV・SALTが違うものになるとdecryptDataが煩雑になると考えました。
        //そのため、同じインスタンスを使う限りは同じIV・SALTを使うことにします。それが嫌なら違うインスタンスを作ればいいのです。

        this.IS_LOGIN_REQUIRED = IS_LOGIN_REQUIRED;

        this.UtilsFunc      = new UtilsFunctions();
        this.preloader      = new PreLoader();

        this.#__initTipFlg();

    }



    async downloadKeyFromFireStore(COLLECTION_NAME:string, DOCUMENT_ID:string,FIELD_NAME:string)              : Promise<string|null>{

        const docRef = doc(this.FIRESTORE_DB, COLLECTION_NAME, DOCUMENT_ID);
        const docSnap = await getDoc(docRef);

        try {


            if (docSnap.exists()) {
              return docSnap.data()[FIELD_NAME];
            } else {
              console.error("APIキーがFirestoreに存在しません");
              return null;
            }
          } catch (error) {
            console.error("APIキーの取得に失敗しました:", error);
            return null;
        }
    }

    deleteData(rawPath : string){
        const USER_PATH : string = `${this.UID}/${rawPath}`;
        const DB_REF_DATA : any  =  ref(this.DB, USER_PATH);

        remove(DB_REF_DATA)
    }

    uploadExpiringCookie(data : any, EXPIRE_AFTER_X_TIME : number = 3000)                   : void{
        var expire        : Date = new Date();
        expire.setTime(expire.getTime()+EXPIRE_AFTER_X_TIME);

        const DB_REF_DATA : any  =  ref(this.DB, `${this.UID}/cookie`);

        //この関数を使用するとき、様々なデータを扱うだろう
        //例えばログイン状態を一時的に保存するために使われる。
        //他には、遷移先のページで実行させたい動作を保存するかもしれない。
        //(例：一度ログイン画面を経由して、設定画面に移動したい時にGogingToSetting:trueのように使う)
        //様々な種類のデータを扱うため、object型で  data.isloginとかdata.isGoingSettingのように
        //使ったほうが　コードが読みやすくなると考えた。そのため、dictionary型を推奨することを
        //console logで表示させる。バグのもとになりそうだからだ。
        if(typeof(data)=="object" && Array.isArray(data) == false){
            //推奨されるデータ型です
        }else{
            this.#__showCaution("uploadExpiringCookie",data);
        }


        const LIST_DATA : [Date, any] = [expire,data];
        const JSON_DATA : string      = JSON.stringify(LIST_DATA);

        set(DB_REF_DATA,JSON_DATA);
    }

    /**
     * @abstract 任意のパス名で、データを保存します。
     * @description 任意のパスを受け取り、 [USER_PATH = GoogleUserID/任意のパス]を作ります。
     * これを使って、firebase realtime databaseに保存します。
     * @param rawPath FirbaseFunction ver2.0.0でdata/KEY_WORDから、KEY_WORDのみでよくなりました。
     * @param data
     */
    uploadData(rawPath : string , data : any)                                               : void{


        const USER_PATH : string = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
                                                            //ログイン必須の場合　　　　ログイン不要の場合

        const DB_REF_DATA : any  =  ref(this.DB, USER_PATH);
        if(typeof(data)=="string"){
            data = ["json",data];
            //JSONにするには、配列でなければならない。
            //そのため、0番目に識別子jsonをつけて配列にする
        }
        const JSON_DATA : string = JSON.stringify(data);
        set(DB_REF_DATA,JSON_DATA);
    }

    prepareUniqueID()                                                                       : string{
        const TEMP_REF  : any = ref(this.DB);
        const ID        : string = push(TEMP_REF).key;//単にユニークIDを生成しているだけです。
        return ID;
    }

    async decryptData(ENCRYPTED_HEX : string, SALT_HEX : string, IV_HEX : string, PASSWORD? : string){
        if(PASSWORD){
            //pass
        }else{
            PASSWORD = "";
        }

        if(this.ACCOUNT_DATA && this.ACCOUNT_DATA.uid){

            const ENCODER                   : TextEncoder = new TextEncoder();
            const DECODER                   : TextDecoder = new TextDecoder();

            const ENCRYPTED_BYTES           : Uint8Array  = new Uint8Array(ENCRYPTED_HEX.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
            const SALT_BYTES                : Uint8Array  = new Uint8Array(SALT_HEX.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
            const IV_BYTES                  : Uint8Array  = new Uint8Array(IV_HEX.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

            const UID                       : number      = this.ACCOUNT_DATA.uid;
            const FIREBASE_CREATE_AT        : number      = this.ACCOUNT_DATA.metadata.createdAt;
            const COMBINED_RAW_KEY          : string      = `${UID}${FIREBASE_CREATE_AT}${PASSWORD}`;

            const COMBINED_BUFFER           : any         = new Uint8Array([...ENCODER.encode(COMBINED_RAW_KEY), ...SALT_BYTES]);
            const HASH_BUFFER               : ArrayBuffer = await crypto.subtle.digest("SHA-256", ENCODER.encode(COMBINED_BUFFER));

            const KEY                       : CryptoKey   = await crypto.subtle.importKey(
                                                                                            "raw",
                                                                                            HASH_BUFFER,
                                                                                            { name: "AES-GCM" },
                                                                                            false,
                                                                                            ["decrypt"]
                                                                                        );

             // データを復号
            try {
                const DECRYPTED_BUFFER = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: IV_BYTES },
                    KEY,
                    ENCRYPTED_BYTES
                );

                const DECRYPTED_STRING = DECODER.decode(DECRYPTED_BUFFER);
                return JSON.parse(DECRYPTED_STRING);
            } catch (error) {
                console.error("復号エラー:", error);
                return null;
            }

        }else{

            console.log(`ログアウト時にFirebaseFunctionsのprepareGoogleUserIDが実行されました。そのため、実行を拒否しました。再試行します。`)
            this.preloader.charWaterflow("SleepTimerMode");
            await this.UtilsFunc.sleep(1000, this.preloader, {preloder:"charWaterflow"});
            this.preloader.closePreLoader("SleepTimerMode");
            this.decryptData(ENCRYPTED_HEX , SALT_HEX , IV_HEX );
        }
    }

    /**
     * @description 同じインスタンスを使う場合、IVとSALTは同じ文字列を使いまわします。
     * これが嫌な場合は、新たにインスタンスを生成してください。
     * @param DATA
     * @param PASSWORD
     * @returns
     */
    async encryptData(DATA : any, PASSWORD? : string)                                       : Promise<void|Record<string,string>>{
        if(PASSWORD){
            //pass
        }else{
            PASSWORD = "";
        }

        if(this.ACCOUNT_DATA && this.ACCOUNT_DATA.uid){
            const UID                   : number      = this.ACCOUNT_DATA.uid;
            const FIREBASE_CREATE_AT    : number      = this.ACCOUNT_DATA.metadata.createdAt;

            const ENCODER               : TextEncoder = new TextEncoder();

            // 2. UID と createAt を結合し、SHA-256 でハッシュ化
            const COMBINED_RAW_KEY      : string      = `${UID}${FIREBASE_CREATE_AT}${PASSWORD}`;
            const COMBINED_BUFFER       : any         = new Uint8Array([...ENCODER.encode(COMBINED_RAW_KEY), ...this.SALT]);
            const HASH_BUFFER           : ArrayBuffer =  await crypto.subtle.digest("SHA-256", ENCODER.encode(COMBINED_BUFFER));

            // 3. AES-GCM 用の暗号鍵を作成
            const KEY                   : CryptoKey   =  await crypto.subtle.importKey(
                                                            "raw",
                                                            HASH_BUFFER,
                                                            {name: "AES-GCM"},
                                                            false,
                                                            ["encrypt"]
                                                        )
             // 4. データを JSON 化して暗号化
            const DATA_STRING           : string      = JSON.stringify(DATA);
            const ENCRYPTED_BUFFER      : ArrayBuffer = await crypto.subtle.encrypt(
                                                                {name:"AES-GCM",iv:this.IV},
                                                                KEY,
                                                                ENCODER.encode(DATA_STRING)
                                                            );

            // 5. 暗号文・ソルト・IV を16進数に変換
            const ENCRYPTED_HEX         : string      = Array.from(new Uint8Array(ENCRYPTED_BUFFER)).map(b => b.toString(16).padStart(2, "0")).join("");
            const SALT_HEX              : string      = Array.from(this.SALT).map(b => b.toString(16).padStart(2, "0")).join("");
            const IV_HEX                : string      = Array.from(this.IV).map(b => b.toString(16).padStart(2, "0")).join("");

            return {data : ENCRYPTED_HEX, salt : SALT_HEX, iv : IV_HEX};
        }else{

            console.log(`ログアウト時にFirebaseFunctionsのprepareGoogleUserIDが実行されました。そのため、実行を拒否しました。再試行します。`)
            await this.UtilsFunc.sleep(1000,this.preloader,{preloder:"charWaterflow"});
            this.encryptData(DATA);
        }
    }

    isEncryptedString(DATA : string)                                                        : boolean{
        const MIN_ENCRYPTED_LENGTH  : number  = 36;
        //dataの文字列を0文字、PASSWORDをアルファベット１文字で登録したときの暗号文字数を調べると
        //36であった。暗号の文字数はデータの文字数とPASSWORDの文字数で増減する。
        //このことから、36が暗号の最小文字数。

        //以下は暗号の可能性があるフラグです trueで暗号かも！！ってことです。
                //暗号である最小文字数よりも、データ文字数がある・・・　怪しいのぉ
        const IS_OVER_LENGTH36              : boolean =  DATA.length >= MIN_ENCRYPTED_LENGTH ? true  : false;
                //英数字以外が含まれていない。空白も。・・・怪しい・・暗号か？
                                                 //英数字以外が含まれていますか？　　　　
        const IS_INCLUDE_NON_ALPHANUMERIC   : boolean =  /[^a-zA-Z0-9]/.test(DATA);
        const IS_ONLY_ALPHABET              : boolean =  /^[a-zA-Z]+$/.test(DATA);
        const IS_ONLY_NUMBER                : boolean =  /^[0-9]+$/.test(DATA);


        const result                        : boolean =  IS_OVER_LENGTH36 &&
                                                         IS_INCLUDE_NON_ALPHANUMERIC === false &&
                                                         IS_ONLY_ALPHABET            === false &&
                                                         IS_ONLY_NUMBER              === false    ? true : false;

        //文字列が３６文字以上　＆　英数字だけで構成されている　＆　英語のみではない　＆　数字だけではない True
        return result;
    }

    isLogined()                                                                             : boolean{

        return this.UID ? true : false;
        //ログインしていたらGoogleのUserIDが保存されてます。
    }

    async downloadExpiringCookie()                                                          : Promise<any>{
        this.#__tellTips("downloadData");

        const DB_REF_DATA : any = ref(this.DB,`${this.UID}/cookie`);
        try {
            const snapshot : any = await get(DB_REF_DATA); // await で結果を待機
            if (snapshot.exists()) { // パスワードが登録されていた場合
                const JSON_DATA     : any    = snapshot.val(); // データを格納

                if(typeof(JSON_DATA)=="string"){
                    var parsedData  : [string, any]  = JSON.parse(JSON_DATA);
                }else{
                    var parsedData  : [string, any]  = JSON_DATA;
                    //例： [0] = "2025-02-26T22:31:38.679Z"
                    //　　 [1] = 保存したデータ
                }

                let EXPIRE_DATE     : Date   = new Date(parsedData[0]); // cookie_dateを格納
                let CURRENT_DATE    : Date   = new Date(); // 現在の時刻を取得

                // cookie_dateから現在時刻までの経過時間をミリ秒で取得
                let ELAPSED_MS_TIME : number = EXPIRE_DATE.getTime() - CURRENT_DATE.getTime();
                // 1000ms(  valid)  = 12:00:03       -  12:00:02
                //    1ms(  valid)  = 12:00:03:0000  -  12:00:02:999
                //    0ms(invalid)  = 12:00:03       -  12:00:03
                //-2000ms(invalid)  = 12:00:03       -  12:00:05

                if (ELAPSED_MS_TIME > 0) {
                    this.#__uploadAndResetInfo();
                    const DICT_DATA : any    =  parsedData[1];
                    return DICT_DATA; // 取得したデータを返す
                } else {
                    //ログイン情報の有効期限が切れた場合は、falseを返す
                    this.uploadData("data/info",`Cookieの有効期限が切れています。
有効期限：EXPIRE_DATE
現在時刻：18
時差：${ELAPSED_MS_TIME/1000}秒`)
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    return false;
                }



            } else {
                console.log('No data available');
                return null;
            }
        } catch (error) {
            error += "   \nin download Expiring cookie"
            this.#__alertMessage(error);
            console.error('Error getting data:', error);
            throw error; // エラーを呼び出し元に伝える
        }
    }

    async downloadData(rawPath : string)                                                    : Promise<any>{
        this.#__tellTips("downloadData");
        const RETRY_COUNT_UPTO  : number = 3;

        for(let retry = 0; retry <= RETRY_COUNT_UPTO; retry++){
            try {
                const USER_PATH         : string = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
                                                                               //ログイン必須の場合　　 ログイン不要の場合
                const DB_REF_DATA       : any    = ref(this.DB, USER_PATH);
                const snapshot  : any    = await get(DB_REF_DATA); // await で結果を待機
                if (snapshot.exists()) { // パスワードが登録されていた場合
                    const JSON_DATA : string = snapshot.val(); // データを格納

                    if(typeof(JSON_DATA)=="string"){
                        var parsedData : any = JSON.parse(JSON_DATA);
                    }else{
                        var parsedData : any = JSON_DATA;
                    }




                    if(Array.isArray(parsedData)){
                        if(parsedData.length >0 && parsedData[0]==="json"){
                            //配列が空だと次の処理が undefined errorとなる。
                            //これを防ぐために parsedData.length>0の条件をはさむ。
                            parsedData  = parsedData[1];
                            //JSONは配列やobject型じゃなければパースできない。
                            //そのため、listに直してからパースしている。
                            //データを取り出す時には、元のデータ（文字列や数値）のみ抽出して返す
                        }
                    }

                    return parsedData; // 取得したデータを返す
                } else {
                    console.log('No data available');
                    return null;
                }
            } catch (error) {
                if(retry == RETRY_COUNT_UPTO){
                    if(this.ACCOUNT_DATA.uid){
                        error += `   \nin download data and uid is ${this.ACCOUNT_DATA.uid}`
                        this.#__alertMessage(error);
                        console.error('Error getting data:', error);
                        throw error; // エラーを呼び出し元に伝える
                    }else{
                        //これは単にログインしてないだけ。
                        return
                    }
                }else{
                    console.log(`In download method, error happend, Retry 2sec later...(${retry})`);
                    await this.UtilsFunc.sleep(2000,{preloder:"charWaterflow"});
                }
            }
        }

    }

    async loginSystem(LoginSystemArgs : LoginSystemArguments)                               : Promise<object|void>{
        //cf. https://www.youtube.com/watch?v=oKDFDCSQNY0
        const IS_LOGINED  : AuthDataType =  await this.#__isLogined();

        var signResult   : any = "";
        if(IS_LOGINED.isLogined){
           signResult  = this.#__logoutFromGoogle(LoginSystemArgs);
        }else{
           signResult  = this.#__loginWithGoogle(LoginSystemArgs);
        }

        return signResult;
    }

    /**
 * @description result に Google アカウントのデータが入ります。以下では何が取得されるかを示します。
 * @example
 * ```js
 * UserCredentialImpl▼
 * operationType            : "signIn"
 * providerID               : "google.com"
 *
 * user▼
 *     accessToken
 *     auth▶
 *     displayName          : "ユーザー名"
 *     email                : "メールアドレス"
 *     emailVerified        : boolean
 *     isAnonymous          : boolean
 *
 *     metadata▼
 *         createAt         : Unixエポック時間（ミリ秒）
 *         creationTime     : Firebaseへ初めて接続した日
 *         lastLoginAt      : Unixエポック時間（ミリ秒）
 *         lastSignInTime   : 最後に Firebase にログインしたとき
 *
 *     phoneNumber          : null
 *     photoURL             : アカウントアイコン画像のURL
 *
 *     proactiveRefresh▶
 *     providerData▶
 *     providerID           : "firebase"
 *     reloadListener       : null
 *     reloadUserInfo▶
 *     stsTokenManager▶     : セキュリティトークンに関するもの
 *     tenantID              : null
 *
 *     uid              : ユーザーの固有ID
 *
 * _tokenResponse▼
 *     context       : ""
 *     displayName   : "ユーザー名"
 *     email         : "メールアドレス"
 *     emailVerified : boolean
 *     expiresIn     : "3600"
 *     federatedID   : "https://accounts.google.com/数字/"
 *     firstName     : "下の名前"
 *     fullName      : "フルネーム"
 *     idToken       : アルファベットの羅列
 *     kind          : ""
 *     lastName      : "苗字"
 *     localID       : ""
 *     oauthAccessToken: ""
 *     oautHEXpireIn  : long型
 *     photoUrl      : アカウントの画像
 *     refreshToken  : ""
 *     rawUserInfo▼  : object型
 *
 *         {
 *             "name"          : "フルネーム",
 *             "granted_scopes": "省略",
 *             "id"            : long型の数字羅列,
 *             "verified_email": boolean,
 *             "given_name"    : "下の名前",
 *             "hd"            : "ホストドメイン @ 以下のもの",
 *             "family_name"   : "苗字",
 *             "email"         : "メアド",
 *             "picture"       : "アカウントアイコンURL"
 *         }
 * ```
 */
    async #__loginWithGoogle(LoginSystemArgs : LoginSystemArguments)     : Promise<boolean>{

        try{
            const result : any = await signInWithPopup(this.AUTH,this.PROVIDER);

            LoginSystemArgs.HTML_BTN_ELEMENT.textContent = "ログアウト";
            LoginSystemArgs.SPAN_NAME.textContent        = `${result.user.displayName}さん　ようこそ`;
            LoginSystemArgs.SPAN_NAME.style.display      = "block";
            this.UID                     = result.user.uid;
            this.ACCOUNT_DATA            = result.user;
            //renderAuthStatus内、#__isLoginedで使われているonAuthStateChangedでは
            //result.userのデータのみ取得できる。さて、ページを閉じても認証状態は残る
            //そんな時、this.ACCOUNT_DATAには２パターンのobjectが存在する可能性がある。
            //UserCredentialImpl直下の全てのデータが入っているobjectか
            //UserCredentialImpl￥userのデータのみか。
            //これは潜在的なバグになる。そのため、this.ACCOUNT_DATAにはあらかじめuser直下のデータだけ
            //保存する。

            this.ACCESS_TOKEN                            = result._tokenResponse.oauthAccessToken;

            this.uploadData("/refreshToken",result._tokenResponse.refreshToken);

            if(LoginSystemArgs.isRedirect && LoginSystemArgs.REDIRECT_METHOD && LoginSystemArgs.CALL_FROM){
                new UrlFunction().redirect({
                                            METHOD      : LoginSystemArgs.REDIRECT_METHOD,
                                            CALL_FROM   : LoginSystemArgs.CALL_FROM,
                                            QUERY       : LoginSystemArgs.QUERY
                                            })
            }
            return true;
        } catch(error:any){
            alert(error);
            this.#__translateSignErrors(error.message);

            return false;

             /**
             * [主なエラーの一覧]
             * auth/popup-closed-by-user　  ：　ユーザーがポップアップを閉じた。認証が未完了。もう一度認証してください。
             * auth/cancelled-popup-request :　すでにほかのポップアップが出ています。以前のポップアップを閉じてください。
             * auth/popup-blocked           :  ブラウザがポップアップをブロックしました。ブラウザの設定でポップアップを許可してください。
             * auth/operation-not-allowed   :　Google認証が有効になっていません。開発者にFirebase Authentificationを確認するよう問い合わせてください。
             * auth/invalid-credential      :　有効期限が切れています。もう一度認証してください。
             * auth/user-disabled           :　Firebaseでユーザーアカウントが無効化されています。開発者にユーザーアカウント名を教えてください。
             * auth/wrong-password          :　パスワードが間違っています。
             * auth/network-request-failed  :　ネットワークエラーです。ネット接続を確認して、再試行してください。
             * auth/too-many-requests       :　短期間に何度もログインされたため、一時的にブロックされています。時間をおいてからお試しください。
             * auth/timeout                 :  ネットワークエラーです。ネット接続を確認して、再試行してください。
             */
        }
    }
    #__logoutFromGoogle(LoginSystemArgs : LoginSystemArguments)    : void{
        signOut(this.AUTH).then( () => {
            LoginSystemArgs.HTML_BTN_ELEMENT.textContent = "ログイン";
            LoginSystemArgs.SPAN_NAME.textContent        = "";
            LoginSystemArgs.SPAN_NAME.style.display      = "none";
            this.UID                     = "";
            this.ACCOUNT_DATA            = {};

            this.uploadData("/token","");//一応削除

            if(LoginSystemArgs.isRedirect && LoginSystemArgs.REDIRECT_METHOD && LoginSystemArgs.CALL_FROM){
                new UrlFunction().redirect({
                                            METHOD      : LoginSystemArgs.REDIRECT_METHOD,
                                            CALL_FROM   : LoginSystemArgs.CALL_FROM,
                                            QUERY       : LoginSystemArgs.QUERY
                                            })
            }
            return true

        }).catch((error:any) => {
            alert(error);
            this.#__translateSignErrors(error.message);

            return false

            /**
             * [主なエラーの一覧]
             */
        });


    }

    /**
     *
     * @returns
     * ```js
     * item.isLogined   : boolean
     * item.accountData : object
     * ```
     * @description #__loginWithGoogle関数と違う点があります。返り値にはresult.userのオブジェクトのみです。
     * @example
     * ```js
     * accessToken
     *     auth▶
     *     displayName          : "ユーザー名"
     *     email                : "メールアドレス"
     *     emailVerified        : boolean
     *     isAnonymous          : boolean
     *
     *     metadata▼
     *         createAt         : Unixエポック時間（ミリ秒）
     *         creationTime     : Firebaseへ初めて接続した日
     *         lastLoginAt      : Unixエポック時間（ミリ秒）
     *         lastSignInTime   : 最後に Firebase にログインしたとき
     *
     *     phoneNumber          : null
     *     photoURL             : アカウントアイコン画像のURL
     *
     *     proactiveRefresh▶
     *     providerData▶
     *     providerID           : "firebase"
     *     reloadListener       : null
     *     reloadUserInfo▶
     *     stsTokenManager▶     : セキュリティトークンに関するもの
     *     tenantID              : null
     *
     *     uid              : ユーザーの固有ID
     * ```
     * @version 1.0.1
     * @abstract
     * Promiseを返すべきなのに、objectを返すことで非同期処理を待たずに読み込むバグがありました。
     * これをPromiseを返すことで解決しました。FirebaseFunction ver 2.2.1の変更点です。
     */
    async #__isLogined()                                                                     : Promise<AuthDataType>{
        return new Promise((resolve) => {  // ✅ Promise を返す
            onAuthStateChanged(this.AUTH, async (result: any) => {
                if (result) {

                    resolve({ isLogined: true, accountData: result });
                } else {
                    resolve({ isLogined: false, accountData: null });
                }
            });
        });
    }

    /**
     * @description 認証状態を読み込み、ユーザーインターフェイスの表示を変えます。
     * @todo        非同期処理をする関数です。これを使う場合は、その後にawait UtilsFunctions().sleep(1000)をしてください。
     * @version 1.0.0
     * @abstract
     * version 1.0.0では、ログイン時に「〇〇さん　ようこそ」と表示させます。
     * ログアウト時には、非表示させます。
     */
    async renderAuthStatus(ARGS : RenderAuthType) : Promise<any>{

        if      (ARGS.METHOD === "signInWithPopup"   ){
            const LOGIN_SYSTEM_ARGS : LoginSystemArguments ={
                                                                HTML_BTN_ELEMENT : ARGS.HTML_BTN_ELEMENT,
                                                                SPAN_NAME        : ARGS.SPAN_NAME,
                                                                isRedirect       : false,
                                                                CALL_FROM        : "in FirebaseFunction, renderAuthStatus, signInWithPopup"
                                                            }

            const RESULT : any = await this.#__loginWithGoogle(LOGIN_SYSTEM_ARGS);

            return RESULT;
            //強制的にログインさせる。

        }else if(ARGS.METHOD === "onAuthStateChanged"){
            const AUTH_DATA : AuthDataType =  await this.#__isLogined();
            const RESULT : any = this.#__applyByAuthStateChange(ARGS,AUTH_DATA)

            return RESULT

        }else if(ARGS.METHOD === "signInWithRedirect"){
             /**
             * <todo> :　まだsignInWithRedirectの機構は完成していません。おそらくこれはそのまま使えますが
             * 未来の私よ　使う時には見直してね
             */
            const RESULT : any  = this.#__applyBySignInWithRedirect()
            //ページが遷移するはずです。
        }

    }

    #__applyByAuthStateChange(ARGS : RenderAuthType, AUTH_DATA : AuthDataType){

        if(AUTH_DATA.isLogined){//ログイン時
            ARGS.HTML_BTN_ELEMENT.textContent   = "ログアウト";
            ARGS.SPAN_NAME.textContent          = `${AUTH_DATA.accountData.displayName}さん　ようこそ`;
            ARGS.SPAN_NAME.style.display        = "block";
            this.UID                            = AUTH_DATA.accountData.uid;
            this.ACCOUNT_DATA                   = AUTH_DATA.accountData;
            //AuthStateChangeではAccess Tokenは取得できません
            return true
        }else{
            ARGS.HTML_BTN_ELEMENT.textContent   = "ログイン";
            ARGS.SPAN_NAME.textContent          = "";
            return false
        }
    }

    async #__applyBySignInWithRedirect(){
        /**
         * <todo> :　まだsignInWithRedirectの機構は完成していません。おそらくこれはそのまま使えますが
         * 未来の私よ　使う時には見直してね
         */
        try{
            await signInWithRedirect(this.AUTH,this.PROVIDER);
        } catch (error){
            alert(`in FirebaseFunctions, renderAuthStatus, __applyBySignInWithRedirect. ログインエラーです。`)
        }

    }
    async doIfThereRedirectResult(ARGS : RenderAuthType){
        /**
         * <todo> :　まだsignInWithRedirectの機構は完成していません。おそらくこれはそのまま使えますが
         * 未来の私よ　使う時には見直してね
         */
        const REDIRECT_RESULT : any = await getRedirectResult(this.AUTH);
        if(REDIRECT_RESULT){
            ARGS.HTML_BTN_ELEMENT.textContent = "ログアウト";
            ARGS.SPAN_NAME.textContent        = `${REDIRECT_RESULT.user.displayName}さん　ようこそ`;
            ARGS.SPAN_NAME.style.display      = "block";
            this.UID                          = REDIRECT_RESULT.user.uid;
            this.ACCOUNT_DATA                 = REDIRECT_RESULT.user;
            this.ACCESS_TOKEN                 = REDIRECT_RESULT._tokenResponse.oauthAccessToken;

            return true
        }else{
            return false;
        }
    }

    #__translateSignErrors(RAW_ERROR_MESSAGE : string){
        const match = RAW_ERROR_MESSAGE.match(/([^)]+)/);
        const EXTRACTED_MESSAGE = match ? match[1] : RAW_ERROR_MESSAGE; // () 内の部分を取得、なければ元のメッセージ



        const RECORD_ERROR_MESSAGE  : Record<string, string> = {
                                                                "auth/popup-closed-by-user"     : "ポップアップを閉じられました。認証が未完了です。もう一度認証してください。",
                                                                "auth/cancelled-popup-request"  : "すでにほかのポップアップが出ています。以前のポップアップを閉じてください。",
                                                                "auth/popup-blocked"            : "ブラウザがポップアップをブロックしました。ブラウザの設定でポップアップを許可してください。",
                                                                "auth/operation-not-allowed"    : "Google認証が有効になっていません。開発者にFirebase Authenticationを確認するよう問い合わせてください。",
                                                                "auth/invalid-credential"       : "有効期限が切れています。もう一度認証してください。",
                                                                "auth/user-disabled"            : "Firebaseでユーザーアカウントが無効化されています。開発者にユーザーアカウント名を教えてください。",
                                                                "auth/wrong-password"           : "パスワードが間違っています。",
                                                                "auth/network-request-failed"   : "ネットワークエラーです。ネット接続を確認して、再試行してください。",
                                                                "auth/too-many-requests"        : "短期間に何度もログインされたため、一時的にブロックされています。時間をおいてからお試しください。",
                                                                "auth/timeout"                  : "ネットワークエラーです。ネット接続を確認して、再試行してください。"
                                                               };
        if(EXTRACTED_MESSAGE in RECORD_ERROR_MESSAGE){
            alert(RECORD_ERROR_MESSAGE[EXTRACTED_MESSAGE]);
        }else{
            alert("サインイン・アウト時に予期せぬエラーが生じました。")
        }
    }

    #__fetchGoogleAccountData()                                                              : object|void{

        onAuthStateChanged(this.AUTH, (user:any) => { // 🔹 `auth` を引数に渡す
            if (user) {
                return user;
            } else {
                alert("Error:未ログイン状態でFirebaseFunctions, #__fetchGoogleAccountDataが実行されました。")
            }
        });

    }

   deleteDataPath(rawPath : string)                                               : void{


        const USER_PATH : string = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
                                                            //ログイン必須の場合　　　　ログイン不要の場合

        const DB_REF_DATA : any  =  ref(this.DB, USER_PATH);
        remove(DB_REF_DATA);
    }

    #__uploadAndResetInfo()                                                                  : void{
        this.uploadData("data/info","");
    }
    #__alertMessage(INFO : any)                                                              : void{

        alert(`Error: yamatoaita@gmail.comにこの文章をお知らせください。
Error info : ${INFO}`)
    }

    #__initTipFlg()                                                                          : void{
        this.isShowTip = {
                            "downloadData" : true

                        }
    }

    #__tellTips(METHOD : string)                                                             : void{
        const GREEN = "color:green";
        const RED = "color:red";
        const BLUE = "color:blue";
        const NORMAL = "color:black;font-weight:normal"
        const BOLD  ="font-weight:bold`"

        if(METHOD == "downloadData" && this.isShowTip["downloadData"]){
            this.isShowTip["downloadData"] = false;

            console.log(
`
============================================================================
|                       %cTip of [downloadData]%c:                             |
|--------------------------------------------------------------------------|
|downloadDataメソッドを実行する際は以下のように使います。                  |
|--------------------------------------------------------------------------|
|    class ClassName{                                                      |
|        constructor(){                                                    |
|            ・・・処理・・・                                              |
|            this.init(); // データ取得後に実行させたいコードは            |
|                        // init関数にくくる。                             |
|        }                                                                 |
|        %casync%c init(){                                                     |
|            const DATA = %cawait%c this.FIREBASE_APP.downloadData("cookie");  |
|            console.log(データが取得後に表示されます‘＄{DATA}‘)         |
|            console.log("このログはその後に表示されます")                 |
|        }                                                                 |
|    }                                                                     |
|--------------------------------------------------------------------------|
|                %cReturnで値を取得したい場合の記載例%c:                       |
|--------------------------------------------------------------------------|
|    %casync%c exampleFunction(){                                              |
|          const VALUE = %cawait%c this.returnFunction();                      |
|    }                                                                     |
|    %casync%c returnFunction(){                                               |
|        const RETURN_VALUE = %cawait%c this.FIREBASE_APP.downloadData("path");|
|        return RETURN_VALUE;                                              |
|    }                                                                     |
|--------------------------------------------------------------------------|
|                %caddEventListenerで行う場合の記載例%c:                       |
|--------------------------------------------------------------------------|
|    setBtnEvent(){                                                        |
|        const BTN = document.getElementById("btn");                       |
|        BTN.addEventListener("click", %casync%c ()=>{                         |
|            const VALUE = %cawait%c this.returnFunction();                    |
|        })                                                                |
|    }                                                                     |
============================================================================
    ` ,`GREEN;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,

    `GREEN;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,

    `GREEN;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`,
    `BLUE;BOLD`,`NORMAL`
   )
        }
    }

    #__showCaution(FUNCTION_NAME : string, ITEM : any)                                       : void{
        var stack : any;
        const ERROR = new Error();

        if(ERROR.stack){
            stack = ERROR.stack.replace("Error","");
            stack = stack.replace(/^\s*at FirebaseFunctions.*$/gm, "");
            if(FUNCTION_NAME=="uploadExpiringCookie"){
                alert(`注意 : アップロードしようとしているものはDictionary型ではありません。

    uploadExpiringCookie関数は仕様上、Dictionary型を渡すことを推奨します。

    渡された値：ITEM   データ型：${typeof(ITEM)}

    現在の行番号：stack`)
            }
        }
    }



}


const PRELOADER_OPTIONS             = ["charWaterflow"] as const
type  PreloaderOptions              = typeof PRELOADER_OPTIONS[number];
type  SleepPreloaderOptions         = {
                                        preloder : PreloaderOptions;
                                      }
const SUBTRACT_DATE_OPTIONS         = ["month","week","day","hour"] as const
type  SubtractDateOptions           = typeof SUBTRACT_DATE_OPTIONS[number];
type  SubtractDateFuncType          = {
                                        targetDate  : Date,
                                        minusAmount : number,
                                        timeUnit    : SubtractDateOptions
                                      }
const WEEKDAY_OPTIONS               = ["long","short"] as const
type  WeekdayOptions                = typeof WEEKDAY_OPTIONS[number];
const MONTH_OPTIONS                 = ["numeric","2-digit","long","short"] as const
type  MonthOptions                  = typeof MONTH_OPTIONS[number];
type  FormatDateOptions             = {
                                        showYear?       : boolean,
                                        showMonth?      : boolean,
                                        monthOption?    : MonthOptions,
                                        showDay?        : boolean,
                                        showHour?       : boolean,
                                        showMinute?     : boolean,
                                        showSecond?     : boolean,
                                        showWeekday?    : boolean,
                                        weekdayOption?  : WeekdayOptions,
                                        isHour12?       : boolean
                                      }

type FormatDateDifferenceOptions    = {
                                        showYear?   : boolean,
                                        showMonth?  : boolean,
                                        showWeek?   : boolean,
                                        showDay?    : boolean,
                                        showHour?   : boolean,
                                        showMinute? : boolean,
                                        showSecond? : boolean
                                      }

/**
 * @description
 * ```
 * 日常使いできる便利な関数を集めました。非同期処理に関係するものや、文字列操作系のものなど。
 * ざっくばらんに集めています。
 * ```
 *
 * @version 1.8.1
 * @abstract
 * ```
 * version 1.0.0
 *          .1.0    calcWeekdayを導入
 *          .2.0    toHarfWidthDegitを導入
 *          .3.0    getLuminance輝度計算関数、
 *                  chooseSuitableFontColor、ちょうどいい字の色を取得関数を導入
 *          .4.0    RGBコードを16進数カラーコードに変換するchangeRGBtoColorCodeを導入
 *                  カラーコードをRGBコードに変換するchangeColorCodeToRGBを導入
 *            .1    getLuminancef輝度計算関数において、RGBだと色成分を正規化されていないバグを修正
 *            .2    changeColorCodeToRGB関数において、色成分が正規化されていたバグを修正。
 *            .3    changeColorCodeToRGB関数において、inputタグ type=colorにvalueで取得した時の
 *                  コンピュータ側の正しいRGBの書き方 rgb(000, 000, 000)(色要素のあとに半角スペース)
 *                  にreturn値を修正。
 *          .5.0    deleteListElem関数を導入。
 *            .1    chooseSuitableFontColor関数において、灰色の選択肢を消去。輝度が0.3以下の場合のみ白、ほかは黒に変更・
 *          .6.0    subtractDates関数を導入。
 *          .7.0    formatDate関数を導入。iso形式の文字列を入れると、オプションに合わせて見やすい時間表示に変えてくれます。
 *          .8.0    provideRandomID関数を導入。ショートカットのような立ち位置。
 *          .8.1    sleep関数において、preloaderを関数内で生成するとmax stackになるため、引数で要求するようにした。
 * ```
 */
class UtilsFunctions{

    constructor(){

    }

    /**
     * @abstract 注意事項:sleepを使う際は使用する関数にasyncをつけ、await sleepとして使います。
     * @param {*} MS
     * @returns
     * @version 1.0.0
     *
     * @example
     * ```js
     *  SomeClass{
     *      UtilsFunc : UtilsFunctions;
     *      constructor(){
     *          this.UtilsFunc =  new UtilsFunctions();
     *      }
     *
     *      async someFunction(){
     *          ーー　何らかの非同期処理のプロセス　　　ーー
     *          await this.UtilsFunc.sleep(1000)
     *          ーー非同期処理が終わったら行うプロセス　ーー
     *      }
     * }
     *  ➡ １秒間　処理を停止します。非同期処理を待つのに便利
     * ```
     */
    async sleep(MS :number,PRELOADER : PreLoader|null, PRELOADER_OPTION? : SleepPreloaderOptions)                                   : Promise<void>{
        console.log(`注意事項\nsleepを使う際は使用する関数にasyncをつけ、await sleepとして使います。`)
        if(PRELOADER && PRELOADER_OPTION){
            if(PRELOADER_OPTION.preloder === "charWaterflow"){
                PRELOADER.charWaterflow("SleepTimerMode");
            }
            await new Promise(resolve => setTimeout(resolve,MS));

            PRELOADER.closePreLoader("SleepTimerMode");
        }else{
            await new Promise(resolve => setTimeout(resolve,MS));
        }

    }

    calcWeekday(MONTH_NUMBER : number, DATE_NUMBER : number)                                        : string|void{
        if(MONTH_NUMBER >= 0 && DATE_NUMBER >= 0){
            const CURRENT_YEAR  : number      = new Date().getFullYear();
            const CURRENT_MONTH : number      = new Date().getMonth();

            const WEEKDAYS      : string[]    = ["日","月","火","水","木","金","土"];

            var   weekdaysIndex : number      = 0;
            if      (MONTH_NUMBER >= CURRENT_MONTH){//今年の場合
                weekdaysIndex = new Date(CURRENT_YEAR,MONTH_NUMBER-1,DATE_NUMBER).getDay();

            }else if(MONTH_NUMBER < CURRENT_MONTH){
                weekdaysIndex = new Date(CURRENT_YEAR+1,MONTH_NUMBER-1,DATE_NUMBER).getDay();

            }



            const WEEKDAY       : string      = WEEKDAYS[weekdaysIndex];
            return WEEKDAY;

        }else{
            const STACK = new Error();
            alert(`${MONTH_NUMBER}月${DATE_NUMBER}日は無効な値です。引数を確かめてください。\n${STACK.message}`)
        }
    }

    subtractDates(OPTION : SubtractDateFuncType)                                              : Date{
        const DATE  : Date = new Date(OPTION.targetDate);
        if      (OPTION.timeUnit === "month"){
            DATE.setMonth(DATE.getMonth() - OPTION.minusAmount    );

        }else if(OPTION.timeUnit === "week"){
            DATE.setDate(DATE.getDate()   - OPTION.minusAmount * 7);

        }else if(OPTION.timeUnit === "day"){
            DATE.setDate(DATE.getDate()   - OPTION.minusAmount    );

        }else if(OPTION.timeUnit === "hour"){
            DATE.setHours(DATE.getHours() - OPTION.minusAmount    );
        }
        return DATE;
    }


    /**
     * @description 数字の文字列のみを引数に渡してください。例:０４２
     * @param FULL_WIDTH_DIGIT
     * @returns
     * @version 1.0.0
     */
    toHarfWidthDegitText(FULL_WIDTH_DIGIT : string)                                                 : string{
        const HARF_WIDTH_DEGIT_STRING : string = FULL_WIDTH_DIGIT.replace(/[０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0));
        //全角の０～９に一致するものを、一文字ずつsに渡します。
        //そして、sのユニコードから0xFEE0だけ削除します。この0xFEE0は半角数字と全角数字の差額になります。
        //便利ですよね。　String.fromCharCode()でユニコードを文字に直します。

        return HARF_WIDTH_DEGIT_STRING;
    }

    /**
     * @description #000000といったhtml色コードやrgb(0,0,0),rgba(0,0,0,0)使って、輝度を求めます
     * @param HEX
     * @returns
     */
    getLuminance(COLOR : string)                                                                      : number{
        var r   : number;
        var g   : number;
        var b   : number;

        if(COLOR.match(/#[a-z0-9]+/g)){//#000000といったhtml色コード
            r   = parseInt(COLOR.slice(1, 3), 16) / 255;
            g   = parseInt(COLOR.slice(3, 5), 16) / 255;
            b   = parseInt(COLOR.slice(5, 7), 16) / 255; //255で割ることで値を0~1に線形輝度計算のため正規化する。

        }else                         {//rgb(0, 0, 0)またはrgba(0, 0, 0, 0)の形式
            const RAW_STRING    : string    = COLOR.replace(/[()rgb]/g,"");//0,0,0 または0,0,0,0の形式
            const COLOR_INDEXS  : string[]  = RAW_STRING.split(",");//[R,G,B,A]に分かれる

            r = parseInt(COLOR_INDEXS[0])/255;
            g = parseInt(COLOR_INDEXS[1])/255;
            b = parseInt(COLOR_INDEXS[2])/255;//255で割ることで値を0~1に線形輝度計算のため正規化する。
        }


        // 色の変換 (0〜1に正規化)
        const LUM = (channel:number) => {
            return (channel <= 0.03928) ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
        };

        // 輝度計算
        const LUMINANCE = 0.2126 * LUM(r) + 0.7152 * LUM(g) + 0.0722 * LUM(b);

        return LUMINANCE;
    }

    chooseSuitableFontColor(BACKGROUND_COLOR : string)                                              : string{
        const LUMINANCE = this.getLuminance(BACKGROUND_COLOR);
        var   fontColor : string = "";
        if      (LUMINANCE <= 0.3){
            fontColor = "#FFFFFF";
        }else{
            fontColor = "#000000";
        }

        return fontColor;
    }

    changeRGBtoColorCode(RGB : string):string|void{
        if(RGB.match(/^rgb/)){
            //例：rgba(255, 255, 255, 0.50)
            const REPLACED_RGB : string|null = RGB.replace(/[rgba()]+/g,"");
            const RGB_ELEMENTS : string[]    = REPLACED_RGB.split(",");
            const R            : number      = parseInt(RGB_ELEMENTS[0]);
            const G            : number      = parseInt(RGB_ELEMENTS[1]);
            const B            : number      = parseInt(RGB_ELEMENTS[2]);

            const toColorCode = (value: number) => value.toString(16).padStart(2,"0");
                                        //カラーコード１６進数に変換　 ↑1桁の場合は0を追加して２桁にする

            const COLOR_CODE   : string      = `#${toColorCode(R)}${toColorCode(G)}${toColorCode(B)}`.toUpperCase();
                                                                                                //大文字にするのは不必要で、好みの問題。
            return COLOR_CODE

        }else{
            alert(`引数の${RGB}はRGBコードではありません。rgb(000,000,000)またはrgba(000,000,000)の形式のコードを渡してください`)
        }
    }

    changeColorCodeToRGB(COLOR_CODE : string):string|void{
        if(COLOR_CODE.match(/^#/)){
            const R     : number   = parseInt(COLOR_CODE.slice(1, 3), 16) ;
            const G     : number   = parseInt(COLOR_CODE.slice(3, 5), 16) ;
            const B     : number   = parseInt(COLOR_CODE.slice(5, 7), 16) ;

            const RGB   : string   = `rgb(${R}, ${G}, ${B})`;
            return RGB
        }else{
            alert(`引数の${COLOR_CODE}は１６進数のカラーコードではありません。#000000の形式のコードを渡してください。`)
        }

    }

    deleteListElem(LIST : any[], ELEM : any):any[]|void{
        const INDEX  : number = LIST.indexOf(ELEM);
        if(INDEX === -1){
            alert(`引数の要素:「${ELEM}」はlistにありませんでした。`);
            console.table(LIST);
        }else{
            const NEW_LIST  : any[] = LIST.filter((item)=>{

                if(item === ELEM){
                    return false;
                }else{
                    return true;
                }
            });//trueになるとfilter関数は、要素を配列に入れます。

            return NEW_LIST;
        }
    }

    /**
     * @abstract chat gpt製の読みやすい日付にする関数です。
     * @param date
     * @returns
     */
    formatDate(iso_date: string, options : FormatDateOptions): string {
        const JP_DATE = new Date( new Date(iso_date).getTime());
        //dateはUTCのISO文字列が入っています。そこに１５時間を足すと、日本時間と一致します。
        //console.log(`hey it is iso date. : ${iso_date}`)
        const ISO8601_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{3})?Z?$/;
        if(ISO8601_PATTERN.test(iso_date)){
            //pass
        }else{
            alert("UtilsFunc, formatDateの引数 iso_dateはISO8061形式にしてください。")
            return "";
        }

        const OPTION_RECORD : Record<string,any> = {timeZone: "UTC"};
        if(options.showYear){
            OPTION_RECORD.year      = "numeric";
        }
        if(options.showMonth){
            OPTION_RECORD.month     = options.monthOption;
        }
        if(options.showDay){
            OPTION_RECORD.day       = "numeric";
        }
        if(options.showHour){
            OPTION_RECORD.hour      = "numeric";
        }
        if(options.showMinute){
            OPTION_RECORD.minute    = "numeric";
        }
        if(options.showSecond){
            OPTION_RECORD.second    = "numeric";
        }
        if(options.showWeekday){
            OPTION_RECORD.weekday   = options.weekdayOption;
        }
        if(options.isHour12){
            OPTION_RECORD.hour12    = true;
        }else{
            OPTION_RECORD.hour12    = false;
        }



        return JP_DATE.toLocaleString(undefined,OPTION_RECORD);
    }

    /**
     * @abstract chat gpt製の日付の差から n年n月n週n日n時間n分n秒のように表示します。
     * オプションによって、表記は変えられます。
     * @param startDate
     * @param endDate
     * @returns
     */
    formatDateDifference(iso_startDate: string, iso_endDate: string, options : FormatDateDifferenceOptions): string {
        //console.log(`iso start : ${iso_startDate},\niso end   : ${iso_endDate}`)
        /**
         * real      : Mon Mar 31 2025 17:00:00
         * iso start : Mon Mar 31 2025 00:00:00 GMT+0900 (日本標準時),
           iso end   : Mon Mar 31 2025 02:00:00 GMT+0900
         */
        var startDate   : Date      = new Date(new Date(iso_startDate).getTime());
        var endDate     : Date      = new Date(new Date(iso_endDate).getTime());
        let diff        : number    = endDate.getTime() - startDate.getTime(); // 差分をミリ秒で取得
        //console.log(`then initial diff [${diff}]`)

        var year        : number    = 0;
        var month       : number    = 0;
        var week        : number    = 0;
        var day         : number    = 0;
        var hour        : number    = 0;
        var minute      : number    = 0;
        var second      : number    = 0;


        if(options.showYear){
            year = Math.floor(diff / (365 * 24 * 60 * 60 * 1000)); // 年を計算(１年ない場合は0が返る)
            diff -= year * (365 * 24 * 60 * 60 * 1000); // 年分の差を引く
        }

        if(options.showMonth){
            month = Math.floor(diff / (30 * 24 * 60 * 60 * 1000)); // 月を計算
            diff -= month * (30 * 24 * 60 * 60 * 1000); // 月分の差を引く
        }

        if(options.showWeek){
            week = Math.floor(diff / (7 * 24 * 60 * 60 * 1000)); // 週を計算
            diff -= week * (7 * 24 * 60 * 60 * 1000); // 週分の差を引く
            //console.log(`in week : ${week}, and diff : ${diff}`)
        }

        if(options.showDay){
            day = Math.floor(diff / (24 * 60 * 60 * 1000)); // 日を計算
            diff -= day * (24 * 60 * 60 * 1000); // 日分の差を引く
            //console.log(`in day : ${day} and diff : ${diff}`)
        }

        if(options.showHour){
            hour = Math.floor(diff / (60 * 60 * 1000)); // 時間を計算
            diff -= hour * (60 * 60 * 1000); // 時間分の差を引く
            //console.log(`in hour : ${hour}, and diff : ${diff}`)
        }

        if(options.showMinute){
            minute = Math.floor(diff / (60 * 1000)); // 分を計算
            diff -= minute * (60 * 1000); // 分分の差を引く
            //console.log(`in minute : ${minute}, and diff : ${diff}`)
        }

        if(options.showSecond){
            second = Math.floor(diff / 1000); // 秒を計算
        }


        // 結果を「n年n月n週n日n時間n分n秒」の形式で返す
        //optionsに応じて表示したり、しなかったり
        return `${year===0 ? "" : `${year}年`} ${month===0 ? "" : `${month}ヵ月`} ${week===0 ? "" : `${week}週間`} ${day===0 ? "" : `${day}日`} ${hour===0 ? "" : `${hour}時間`} ${minute===0 ? "" : `${minute}分`} ${second===0 ? "" : `${second}秒`}`;
    }

    provideRandomID(){
        return self.crypto.randomUUID();
    }


}




/**
 * @abstract UrlFunctionのredirectメソッドで使うデータです
 */
type RedirectData = {
    METHOD      : "toSelectedPage"|"toHP";
    PAGE_TITLE? : string;
    CALL_FROM   : string;
    QUERY?      : any   ;
};
/**
 * @description local環境とGithubPageに互換性を！ 互換性をもってページ遷移を行う処理をできます。
 * またページタイトルを抽出できます。
 * @version 2.5.5
 * @abstract
 * version 2.0.0 redirectメソッドを追加。typescriptに準拠して、より完結にページ遷移できるようになりました。
 *           1.0 redirectメソッドのオプションを分かりやすくしました。toHPとtoSelectedPage
 *           2.0 クラス名をUrlFunctionからUrlFunctionに変えました。
 *           3.0 redirect関数にクエリを指定できるように変えました
 *               これを実装するために__convertDataToQueryStringを導入。
 *           4.0 extractQueryでクエリを取得できるようにしました。
 *             1 Queryが含まれている場合に、composeURLbyPageTitleおよびreturnHomepageURLがエラーをはく
 * 　　　　　　　　バグを__deleteQueryPartを導入し、クエリ箇所を削除することで対策しました
 *      　　　　2 extractHtmlTitleの正規表現において、語末が必ず.github.ioか.htmlでなければ一致しないバグを
 * 　　　　　　　　()?とすることで任意に修正しました。
 *             3 全ての正規表現において、yamatoaita.github.ioからアプリ開発用アカウントsyuubunndou.github.ioに変更しました。
 *           5.0 ついに、Meta社でリンクを開いたときに末尾につく /?fb...(文字列)...　によってUrlFunctionが作動しないバグを修正しました
 *               URLオブジェクトにurlを入れることで、クエリ部分を削除することで対応しました。
 *             1 call fromをredirect関数でもらっているのに、エラー時にそれを表示しなかった仕様を修正
 *             2 composeURLbyPageTitleの以下の部分を削除しました。これはgithub.pageであると、returnが常にエラーになるためです。
 *                   const FUNDATIONAL_PAGE_NAME : string|void = this.extractHtmlTitle(FUNDATIONAL_URL, CALL_FROM);
 *                   if(FUNDATIONAL_PAGE_NAME == PAGE_TITLE){ // Github.2.
 *                       alert(`ホームページ名とPAGE_TITLEは違う名前でなければなりません。\n〇　https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html\ncall from${CALL_FROM}`)
 *                       //無効なURL✖　 https://syuubunndou.github.io/ホームページ名.github.io/ホームページ名.html
 *                   }else{
 *               また、この記述はあくまでも開発時のエラーを明示するだけなので、削除しても問題ないと判断しました。
 *             3 ファイル名にエスケープ文字(%と数字)が含まれている場合にマッチしなかったので、
 *               正規表現const PAGE_TITLE_REG_WITH_SYNBOLE = /\/([a-zA-Z_.・},@%]*)\.html$/;
 *             　このように更新しました。
 *             4 なぜかcomposeURLByPageTitleのgithub3の処理記述を全て削除していたので　付け戻しました。
 *             5 extractQuery関数にて、クエリ部分がobject{}ではなくstringの場合に、取得できないバグを修正しました。
 *
 */
class UrlFunction{
    constructor(){

    }
    extractHtmlTitle(rawHtml : string, CALL_FROM : string)                                             :string|void{
        //https:syuubunndou.github.io/page-tile.github.io/
        //http://127.0.0.1:5500/parent-file-name/page-title.html
        //https://syuubunndou.github.io/scheduler.github.io/adjust.html?user_index=user

        const url = new URL(rawHtml);

        let htmlLink = url.pathname; // クエリを含まないパス部分を取得

        htmlLink = htmlLink.replace(/\/$/,"");
        //https:syuubunndou.github.io/page-title.github.io
        //http://127.0.0.1:5500/parent-file-name/page-title.html
        //https://syuubunndou.github.io/scheduler.github.io/adjust.html?user_index=user

        var configured_item : string |undefined= htmlLink.split("/").pop();
        //page-title.github.io
        //page-title.html
        //adjust.html?user_index=user
        if(configured_item){

            const MATCHED_ITEMS : RegExpMatchArray|null = configured_item.match(/^(.+)(?:\.github\.io|\.html)?\/?$/);
            if(MATCHED_ITEMS){

                var htmlTitle : string = MATCHED_ITEMS[1];
                //正規表現の解説
                //^(.+)で文字の頭にある何文字かの文字列をキャプチャする
                //?:で「これは非キャプチャグループです。ORのために使っています」と宣言
                //(?:  \.github\.io | \.html)で.github.ioか.htmlを指定している。
                //最後、[1]とすることで一番目のキャプチャ内容を取得する

                //結果の例
                //page-title
                //page-title
                //adjust
                htmlTitle = htmlTitle.replace(".html","");//語末に.htmlなる時は強制敵に削除
                htmlTitle = htmlTitle.replace(/\?.*$/,"");
                return htmlTitle;
            }else{
                alert(`Error: Utils.js, UrlFunction, extractHtmlTitle, 正規表現に一致しませんでした。htmlLink is ${htmlLink}, Reg is ^(.+)(?:\.github\.io|\.html)?\/?$\ncall from ${CALL_FROM}`)
            }
        }else{
            alert(`Error: Utils.js, UrlFunction, extractHtmlTitle, configured_item is undefined. htmlLink is ${htmlLink}\ncall from ${CALL_FROM}`)
        }


    }

    /**
     * @description -ローカル環境とgithub.pageではurlの形式が異なります。そのため、ページ事に遷移先のURLを別処理で作成する必要があるのです。
     * @param {*} URL -URL:window.location.hrefがデフォルト値
     * @param {*} PAGE_TITLE -PAGE_TITLE:遷移先のページ名を指定
     * @returns 指定したページ名を含むURLリンクを返します。
     *
     */
    #__composeURLbyPageTitle(PAGE_TITLE : string , CALL_FROM : string, URL : string =window.location.href)  : string|void{
        /*[URLの例]
        【ローカル環境】

        http://127.0.0.1:5500/parent-file-name/page-title.html

        （例1）https://syuubunndou.github.io/ホームページ名.github.io/
        （例2）https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html
        （例3）https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html?user_index=user

        →ローカル環境とgithub.pageで条件分岐しよう。
        　ローカル環境の場合は正規表現で置換

        [github.pageの場合]
        github.pageの場合は末尾に/サブページ名.htmlを追加しよう。
        ↓↓
        （例1）〇　https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html
        （例2）✖　https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html/サブページ名.html
        （例3）✖  https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html?user_index=user/サブページ名.html

        もしURLがすでにサブページ出会った場合は違う処理をしよう。サブページを抽出し、PAGE_TITLEに置換する。


        github.pageはhttps://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html
        という形式だ。
        PAGE_TITLEがホームページ名と一緒になることはない。↓

        ✖ https://syuubunndou.github.io/INDEX.github.io/INDEX.html

        そのため、FUNDATIONAL_URLのホームページ名とPAGE_TITLEが違う名前か確かめないとね。

        〇https://syuubunndou.github.io/scheduler.github.io/adjust.html
        */


        /*
        1.ローカル環境かgithub.pageか判断し、条件分岐する　： if(URL.match(/github/)){}

            Local.1. 正規表現を使って、page-title.htmlの部分を置換する。
            　　　　　（例）http://127.0.0.1:5500/utils/index.html
            　　　　　　　→ http://127.0.0.1:5500/utils/login.html

            Github.1. ホームページ名のみの基本URLを抽出する : URL.match(/https:\/{2}syuubunndou.github.io\/[\w-]*\.github\.io\//)[0];
            　　　　　（例1）https://syuubunndou.github.io/ホームページ名.github.io/
                        → https://syuubunndou.github.io/ホームページ名.github.io/

                    （例2）https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html
                        → https://syuubunndou.github.io/ホームページ名.github.io/

                    （例3）https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html?user_index=user/サブページ名.html
                        → https://syuubunndou.github.io/ホームページ名.github.io/

            Github.2. ホームページ名と変更したいPAGE_TITLEが同じか判断し、条件分岐する
            　　　　　　合致した場合は無効なURLとなるため、alertでお知らせする。

            Github.3.　現在のＵＲＬはサブページか判断して、条件分岐する。
            　　　　
                Github.4.hp.   ＵＲＬの末尾にPAGE_TITLE.htmlを加える。

                Github.4.subp. ＵＲＬ（https://syuubunndou.github.io/ホームページ名.github.io/サブページ名.html）
                　　　　　　　　 のサブページ名をPAGE_TITLEに置換する。
        */

        const PAGE_TITLE_REG_WITH_SYNBOLE = /\/([a-zA-Z0-9_.・},@%]*)\.html$/;
        //Windowsで認められている使用可能な文字は _ - . ・ ( ) [ ] { } , @が主なものである。
        //これらを含めたファイル名でもマッチできる正規表現にした。漢字やひらがなはエラーになる。

        URL = this.__deleteQueryPart(URL);

        if(URL.match(/github/)){//1

            const MATCHED_ITEMS : RegExpMatchArray |null= URL.match(/https:\/{2}syuubunndou.github.io\/[/w/.]*/);
            if(MATCHED_ITEMS){
                const FUNDATIONAL_URL       :string       =  MATCHED_ITEMS[0];
                //                                  https:  syuubunndou.github.io hp-name",
                //Github.1.
                //→https://syuubunndou.github.io/ホームページ名/サブページ名.html   から
                //→https://syuubunndou.github.io/ホームページ名/　　　　　　　　　  が抽出される。
                //HP名には２パターンがある。　NAME/ と NAME.github.io/ である。

                if(URL.match(/\.html$/)){//Github.3. サブページ名にのみ　末尾に.htmlがつくのです。

                    const IS_MATCH  : boolean = URL.match(PAGE_TITLE_REG_WITH_SYNBOLE) ? true : false ;
                    if(IS_MATCH){
                        var composedURL : string  = URL.replace(PAGE_TITLE_REG_WITH_SYNBOLE,`/${PAGE_TITLE}.html`);
                        //                             /subpage.html  , / page-title  .html　　　に置換
                        return composedURL;

                    }else{
                        alert(`ファイル名エラーです。htmlファイル名にひらがなや漢字が含まれていませんか？ url : ${URL}`)
                    }
                    //Github.4.subp

                }else{
                    var composedURL : string = `${URL}${PAGE_TITLE}.html`;
                    //                ・・・/   page-title .html　　　末尾に加える
                    //Github.4.hp.

                    return composedURL;
                }


            }else{
                alert(`Error: Utils.js, UrlFunctions, composedURLbyPageTitle, 正規表現にマッチしたものはありません。URL is ${URL} \ncall from${CALL_FROM}`);

                return
            }


        }else{
            console.log(`url  : ${URL}`)
            const IS_MATCH  : boolean = URL.match(PAGE_TITLE_REG_WITH_SYNBOLE) ? true : false ;
            if(IS_MATCH){
                var composedURL : string = URL.replace(PAGE_TITLE_REG_WITH_SYNBOLE,`/${PAGE_TITLE}\.html`);
                //　　　　　　　　　　　　　　　        　/  target .html　          ,　/  page-title .html
                //Local.1.
                return composedURL;

            }else{
                alert(`ファイル名エラーです。htmlファイル名にひらがなや漢字が含まれていませんか？ url : ${URL} \ncall from${CALL_FROM}`)
            }
        }
    }

    /**
     * @description ホームページのURLを作り返します。ローカル環境とgithub.pageでは処理を変えています。どちらもURLはwindow.location.hrefで取得したものを使用します。
     * @param {*} homePageTitle homePageTitleはローカル環境で使用します。デフォルトがindexです。github.pageにアップしたのちには読み込まれません。
     * @returns 　http://127.0.0.1:5500/utils/index.htmlやhttps://syuubunndou.github.io/scheduler.github.ioのように返します。
     */
    #__returnHomePageURL( CALL_FROM : string,homePageTitle : string ="index")                              : string|void{
        const URL = this.__deleteQueryPart(window.location.href);


        if(URL.match(/github/)){
            const MATCHED_ITEMS : RegExpMatchArray|null =   URL.match(/https:\/{2}syuubunndou.github.io\/[\w\.]*\//);
            if(MATCHED_ITEMS){
                var gitHomePageURL : string = MATCHED_ITEMS[0];
                //                            https://   syuubunndou.github.io// NAME  //
                //➡https://syuubunndou.github.io/linktree/index.html　　が
                //  https://syuubunndou.github.io/linktree/　　　　　　　になります
                return gitHomePageURL;
            }else{
                alert(`Error: Utils.js, UrlFunction, returnHomePageURL, 正規表現にマッチしたものはありません。 URL is : ${URL}\ncall from${CALL_FROM}`);

                return
            }

        }else{
           // console.log(`here you are\nhomepege title : ${homePageTitle},and call from : ${CALL_FROM}\n url : ${URL}`)
            var localHomePageURL : string|void = this.#__composeURLbyPageTitle(homePageTitle, CALL_FROM, URL);
            return localHomePageURL;
        }
    }

    __deleteQueryPart(URL : string)                                                 : string{
        const URL_COMPONENTS : string[] = URL.split("?");
        if(URL_COMPONENTS.length>1){
            return URL_COMPONENTS[0];
        }else{
            return URL
        }

    }

    /**
     * @description 簡単にlocal環境とGithubPageの互換性を保ちながらページ遷移ができます。typescript準拠の関数です
     * @abstract　全てのメソッドはstring|voidが返り値です。なので、if(RETURN_ITEM)のコードで判断機構を挟みます。
     *          　これをUrlFunctionの外で毎回かくのがいやになりました。なので、このクラス内部で完結させます。
     *          ```
     *             RedirectData{
     *                  METHOD      : "composeURLbyPageTitle"|"returnHomePageURL";
     *                  PAGE_TITLE? : string;
     *                  CALL_FROM   : string;
     *                  QUERY?      : any; (=> データをそのまま入れてください。勝手にクエリ用に編集します）
     *             }
     *          ```
     */
    redirect(REDIRECT_DATA : RedirectData)                                          : void{

        if(      REDIRECT_DATA.METHOD === "toSelectedPage"){

            if(REDIRECT_DATA.PAGE_TITLE){
                var url = this.#__composeURLbyPageTitle(REDIRECT_DATA.PAGE_TITLE, REDIRECT_DATA.CALL_FROM)
                if(REDIRECT_DATA.QUERY){
                    let query = this.__convertDataToQueryString(REDIRECT_DATA.QUERY);
                   url += `?data=${query}`
                }

                if(url){
                    window.location.href = url;
                }else{
                    this.alertError("composeURLbyPageTitle",`${REDIRECT_DATA.CALL_FROM}, 無効なURLでした。URL:${window.location.href}`)
                }
            }else{
                alert(`in UrlFunction, redirect. composeURLbyPageTitleが引数に渡されました。しかし、必要なPAGE_TITLEが引数にありません。指定してください。\ncall from`);
            }

        }else if(REDIRECT_DATA.METHOD === "toHP"    ){

                var url = this.#__returnHomePageURL(REDIRECT_DATA.CALL_FROM,"index");
                if(REDIRECT_DATA.QUERY){
                    let query = this.__convertDataToQueryString(REDIRECT_DATA.QUERY)
                    url += `?data=${query}`
                }
                if(url){
                    window.location.href = url;
                }else{
                    this.alertError("returnHomePageURL",`${REDIRECT_DATA.CALL_FROM}, 無効なURLでした。URL:${window.location.href}`)
                }
        }

    }

    __convertDataToQueryString(DATA : any)                                          : string{

        var query_string : string = "";
        if(typeof(DATA)=== "object"){
            query_string =  encodeURIComponent(JSON.stringify(DATA));
        }else{
            query_string = DATA;
        }

        return `${query_string}`;
    }

    extractQuery()                                                                  : any{
        const URL_PARAMS : URLSearchParams = new URLSearchParams(window.location.search);
        const QUERY_VALUE : string|null     = URL_PARAMS.get(`data`);
        if(QUERY_VALUE){
            try {
                // 1. JSON.parseを試みる
                const PARSED_DATA: any = JSON.parse(QUERY_VALUE);

                // パースが成功したら、パースされたデータ（オブジェクトまたは配列など）を返す
                return PARSED_DATA;

                } catch (e) {
                    // 2. JSON.parseが失敗した場合（文字列がJSON形式ではない場合）
                    // エラーが発生したので、QUERY_VALUEはただの文字列と判断し、そのまま返す
                    return QUERY_VALUE;
                }
        }else{
            console.log("URLFUNCTION: extractQuery: クエリパラメータ 'data' は存在しません。");
            return "";
        }

    }
    /**
     * @abstract 全てのメソッドはstring|voidが返り値です。なので、if(RETURN_ITEM)のコードを挟みます。このelse
     * 　　　　　の場合の記述を毎回書くのが面倒なので、このメソッドを追加しました。
     * @param METHOD_NAME
     * @param INFO
     */
    alertError( METHOD_NAME : "extractHtmlTitle"|"composeURLbyPageTitle"|"returnHomePageURL" ,
                INFO : string
              )
                                                       : void{

        alert(`Error: in UrlFunction, ${METHOD_NAME}, ${INFO}`);
        console.log(`Error: in UrlFunction, ${METHOD_NAME}, ${INFO}`);
    }


}


//リテラル型インデックスを使ったユニオン型の生成
const VALIDATION_OPTIONS = ["lengthWithin"           ,
                            "onlyNumbers"            ,
                            "onlySelectedNumberRange",
                            "zeroPadding"            ,
                            "withinMonthlyDate"      ,
                            "renderWeekday"           ] as const
type ValidateOption = typeof VALIDATION_OPTIONS[number];
type SetValidationType = {
    CONTENT_ELEMENTS : HTMLDivElement[]|HTMLSpanElement[],
    VALIDATE_OPTION  : ValidateOption[],
    LENGTH?          : number,
    MIN_NUMBER?      : number,
    MAX_NUMBER?      : number,
    MONTH_ELEMENT?   : HTMLDivElement|HTMLSpanElement,
    DATE_ELEMENT?    : HTMLDivElement|HTMLSpanElement

}
type LastLaunchTimeType = {
    [key : string] : Date;
};
/**
 * @description
 * ```js
 * HTML elementにかかわる便利なメソッドを集めました。
 * ```
 * @version 5.1.0
 * @abstract
 * ```js
 * version 1.0.0 setPlaceHolderを導入
 *           1.0 setValidationを導入
 *
 * version 2.0.0 リテラル型インデックスを使ったユニオン型の生成法を導入。
 *               これによって、複数のオプションを一気にさばけるようになりました。
 *           1.0 各メソッドにおいて、同じplaceholderを表示するものを一括設定できるようになりました。
 *           2.0 validation option [onlyNumbers]を導入
 *           3.0 validation option [onlySelectedNumberRange]を導入
 *           4.0 validation option [zeroPadding]を導入
 *            .1 zeroPaddingにおいて、00から1を入力すると、01ではなく1になるバグを修正
 *           5.0 validation option [withinMonthlyDate]を導入
 *            .1 withinMonthlyDateにおいて、月Elementと日Elementを相互に関係づけました。
 *           6.0 validation option [renderWeekday]を導入
 *            .1 setPlaceHolderを行った場合にスムーズに入力できなくなるバグを修正
 *            .2 calcWeekdayをUtilsFunctionに移植しました。
 *            .3 __onlySelectedNumberRangeにおいて、delキーを押すと空欄になるバグを修正しました。
 *            .4 ➡ ver 2.6.3において、delキーを押して空欄にならないようにしましたが、逆にほかの月を選択しにくくなったため、
 *               もとに戻しました。
 *               例えば01の状態で、02~12まで入力がalert(範囲外です）によって、できなくなったのです・・・
 *
 * version 3.0.0 様々なvalidationで使われる基盤関数　onlyNumberが全角数字を自動的に半角数字に処理することができるようになりました。
 *               また、これを実現するためにdebounce timeの概念を導入しました。付随して、__isLaunchEventを導入してdebounceの範囲内か
 *            　 しらべることができるようになりました。ユーザーがストレスフリーに柔軟にできるようになったのです。
 *
 * version 4.0.0 divとspanエレメントに加えて、inputエレメントも対応するようになりました。
 *               getRawText関数とsetValueToContentElement関数を導入することで実現しました。
 *            .1 setPlaceHolder関数において、常にtextcontentまたはvalueとして挿入するバグを修正しました。
 *           1.0 alignSpanToAdjacentInputCenterというバグまみれの汎用なのかわからん関数を導入
 *           2.0 入力必須だが、未入力である場所を知らせるシグニファイヤーを追加する関数
 *               setUnfilledSignifierを導入
 *
 * version 5.0.0 placeHolder関数の仕様を大幅変更。placeHolderをする際には毎回インスタンスを生成
 * 　　　　　　　　するように仕様を変更。
 * 　　　　　　　　placeHolderのイベントを後々削除するdeletePlaceholderEvent関数を導入
 *               placeHolderイベントを分離した#__resetPlaceHolderを導入
 *           1.0 changeImage関数を導入。動的にImageを変更できるようになりました。
 * ```
 */
class HtmlFunction{
    UtilsFunc       : UtilsFunctions;
    debounceTime    : number;
    lastLaunchTimes : LastLaunchTimeType;

    PLACEHOLDER_ELEM: any;
    constructor(){
        this.UtilsFunc = new UtilsFunctions();
        this.debounceTime = 50; // 50ミリ秒以上経過したら、次のイベントを発火してよい。
        //前回の発火時間　｜　　今の時間       | 時間の差（ミリ秒）　| 発火可能？
        //11:00:00:001       11:00:01:000  　  999ms　　　　　　　　OK
        //11:00:00:001       11:00:00:010        9ms              NO
        //11:00:00:000       11:00:00:050       50ms              OK
        this.lastLaunchTimes = {};

        this.PLACEHOLDER_ELEM = "";
        this._boundResetPlaceHolder = this.#__resetPlaceHolder.bind(this);
        //setPlaceHolderはentry系のエレメントのsignifier的文字列を表示・非表示するイベントを設置する関数である。
        //さて、entry系のエレメントは時に「ボタンを押したらプログラムが設定した値が入力される」
        //といった機能を実装することがある。TaskManagerの基本色ボタンがそうだ。
        //さて、すでに値が入力されている場合にはsetPlaceHolderのイベントは削除されてほしい。
        //さもなければ、値を編集しようとしたらば消えてしまったり、灰色のままだったりする
        //そこで、イベントを無名関数ではなく有名関数で登録して、削除しようとした
        //しかし、ここでアロー関数ならthisを保存してくれるが、有名関数の場合thisが保存されない。
        //厳密にはthisがCONTNE_ELEMENTを指すようになるらしい。
        //そんなPythonにはない嫌な仕様を乗り越えるため、ChatGPTが教えてくれたのがprivateでthisをbind
        //する方法である。privateでthisをbindしないと、イベント処理が正常にならない。
        //結論、pythonのselfは最高。
    }

    /**
     * @description エレメントにクリックするまで任意の文字を表示します
     * @param DIV_CONTENT_ELEMENT
     * @param PLACE_HOLDER_INNER_HTML elem.innerHTMLで入力する内容を書きます。
     * @version 1.1.1
     * @abstract
     * ```js
     * version 1.0.0
     *           1.0 PlaceHolderに表示する文字を変えられるようにしました。
     *           1.1 addEventListenerを一度のみに。じゃないと、毎回消えるから。
     *         2.0.0 後々イベントを削除できるように変更。
     * 　　　　　　　　これを実装するために、placeholder関数時には毎回new HtmlFunctionのインスタンスを作る仕様に変更
     * ```
     */
    private _boundResetPlaceHolder : () => void;
    setPlaceHolder(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement, PLACE_HOLDER_TEXT : string)             : void{
        if(this.PLACEHOLDER_ELEM){
            console.log("ヒント：setPlaceHolderを使用するときには\nnew HtmlFunction()で毎回インスタンスを生成してください。")
            //二回この関数が呼ばれる時は、HtmlFunctionインスタンスを使いまわしていることになる
            //その場合は、ヒントを表示する。
        }
        if(CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement){
            CONTENT_ELEMENT.innerHTML   = PLACE_HOLDER_TEXT;
        }else if(CONTENT_ELEMENT instanceof HTMLInputElement){
            CONTENT_ELEMENT.value       = PLACE_HOLDER_TEXT;
        }
        CONTENT_ELEMENT.style.color = "rgb(153, 153, 153)"

        CONTENT_ELEMENT.addEventListener("focus",this._boundResetPlaceHolder,{once:true});
        this.PLACEHOLDER_ELEM = CONTENT_ELEMENT;
    }
    #__resetPlaceHolder(){

        this.#__setValueToContentElement(this.PLACEHOLDER_ELEM,"");
        this.PLACEHOLDER_ELEM.style.color = "rgb(0, 0, 0)"
        this.PLACEHOLDER_ELEM.focus();
    }
    deletePlaceholderEvent(){
        this.PLACEHOLDER_ELEM.removeEventListener("focus",this._boundResetPlaceHolder);
        this.PLACEHOLDER_ELEM.style.color = "rgb(0, 0, 0)"
        this.PLACEHOLDER_ELEM.focus();
    }


    setUnfilledSignifier(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement){
        CONTENT_ELEMENT.style.backgroundColor = "rgb(255, 208, 0)";
        CONTENT_ELEMENT.addEventListener("focus",()=>{
            CONTENT_ELEMENT.style.backgroundColor = "rgb(255,255,255)";
        },{once:true});
    }

    setValidation(VALIDATION_DATA : SetValidationType)                                                                  : void{
        const OPTIONS       : string[]      = VALIDATION_DATA.VALIDATE_OPTION;

        for(let option of OPTIONS){

            for(let element of VALIDATION_DATA.CONTENT_ELEMENTS){

                if      (option === "lengthWithin"           ){

                    if(VALIDATION_DATA.LENGTH){
                        this.#__validateLengthWithin(element,VALIDATION_DATA.LENGTH)
                    }else{
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数LENGTHがありません。`)
                        break
                    }

                }else if(option === "onlyNumbers"            ){
                    this.#__onlyNumbers(element);

                }else if(option === "onlySelectedNumberRange"){

                    if(typeof VALIDATION_DATA.MAX_NUMBER === "number" && typeof VALIDATION_DATA.MIN_NUMBER === "number"){
                        this.#__onlySelectedNumberRange(element,VALIDATION_DATA.MIN_NUMBER,VALIDATION_DATA.MAX_NUMBER);
                    }else{
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数MIN_NUMBERとMAX_NUMBERがそろっていません。`)
                        break
                    }

                }else if(option === "zeroPadding"            ){
                    this.#__zeroPadding(element);

                }else if(option === "withinMonthlyDate"      ){

                    if(VALIDATION_DATA.MONTH_ELEMENT){
                        this.#__withinMonthlyDate(element,VALIDATION_DATA.MONTH_ELEMENT);
                    }else{
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数MONTH_ELEMENTがありません。`)
                        break
                    }

                }else if(option === "renderWeekday"          ){
                    this.#__renderWeekday(element,VALIDATION_DATA.MONTH_ELEMENT!,VALIDATION_DATA.DATE_ELEMENT!);
                }

            }

        }
    }

    #__getRawText(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement) : string|null{
        var   rawText   : string|null   = "";
        if      (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement){
            rawText = CONTENT_ELEMENT.textContent;
        }else if(CONTENT_ELEMENT instanceof HTMLInputElement){
            rawText = CONTENT_ELEMENT.value
        }

        return rawText;
    }
    #__setValueToContentElement(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement , VALUE : string) : void{
        if      (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement){
            CONTENT_ELEMENT.textContent = VALUE;
        }else if(CONTENT_ELEMENT instanceof HTMLInputElement){
            CONTENT_ELEMENT.value = VALUE;
        }
    }

    #__validateLengthWithin(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement, LENGTH : number)                          : void{
        CONTENT_ELEMENT.addEventListener("input",()=>{
            var text        : string|null = this.#__getRawText(CONTENT_ELEMENT);
            var textLength  : number;

            if(text){
                textLength = text.length;
                if(textLength > LENGTH){
                    this.#__setValueToContentElement(CONTENT_ELEMENT,text.slice(0,-1));
                    this.#__setCursorToEnd(CONTENT_ELEMENT);
                }else{
                    return
                }
            }else{
                return
            }


        })
    }

    #__setCursorToEnd(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement)                                                 : void{
        if(CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement){
            const RANGE     : any  = document.createRange();
            const SELECTION : any  = window.getSelection();

            RANGE.selectNodeContents(CONTENT_ELEMENT);//全ての内容を選択
            RANGE.collapse(false);                    //末尾にカーソルを移動

            SELECTION.removeAllRanges();
            SELECTION.addRange(RANGE);

        }else if (CONTENT_ELEMENT instanceof HTMLInputElement) {
            // 入力欄の内容全体を選択して、カーソルを末尾に移動
            const length    : number = CONTENT_ELEMENT.value.length;

            // カーソル位置を末尾にセット
            CONTENT_ELEMENT.setSelectionRange(length, length);

            // 入力欄にフォーカスを戻す
            CONTENT_ELEMENT.focus();
        }
    }

    #__onlyNumbers(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement)                                                    : void{
        this.lastLaunchTimes.onlyNumbers = new Date();
        //init 処理
        CONTENT_ELEMENT.addEventListener("input",()=>{
            if(this.#__isLaunchEvent("onlyNumbers")){

                const RAW_TEXT      : string|null = this.#__getRawText(CONTENT_ELEMENT);

                if(RAW_TEXT){
                    const IS_NUM    : boolean     = RAW_TEXT.match(/^[0-9０-９]+$/) ? true : false ;

                    if(IS_NUM){
                        //pass
                        var fullWidthDigit = this.UtilsFunc.toHarfWidthDegitText(RAW_TEXT);
                        this.#__setValueToContentElement(CONTENT_ELEMENT,fullWidthDigit);
                    }else{
                        alert(`数値以外が入力されたため、文字を消去しました。`)
                        this.#__setValueToContentElement(CONTENT_ELEMENT,RAW_TEXT.replace(/[^0-9]+/g,""));
                    }

                }

                this.lastLaunchTimes.onlyNumbers = new Date();

            }else{//debounce timeの有効期限内であったため、続けての処理が拒否される
                const RAW_TEXT  : string|null = this.#__getRawText(CONTENT_ELEMENT);
                if(RAW_TEXT){
                    //これは全角数字に対する処理です。
                    //全角数字を入力すると次のようなことが起きます。

                    /*
                    1.全角数字１がinputされる(この時はまだ、IMEの管轄。入力が未確定です。textContentには全角数字が入るけど。変換可能)
                    2.onlyNumberイベントが発火して、textContentに半角数字にした1が挿入される。(＝1)
                    3.IMEの変換を確定させて、１をinputする
                    4.onlyNumberイベントが発火する。debound timeによって、処理を拒否される。

                    結果：1１(半角と全角)になる。
                    */

                    //このように、余分な全角数字が後から入力されます。そのため、50ミリ秒以内に続けて実行された条件で
                    //文字列から全角数字を全て消去します。
                    this.#__setValueToContentElement(CONTENT_ELEMENT,RAW_TEXT.replace(/[^0-9]/g,""));
                    return
                }

            }
        })


    }

    #__onlySelectedNumberRange(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement,MIN_NUMBER : number, MAX_NUMBER : number): void{
        this.#__onlyNumbers(CONTENT_ELEMENT);//0~9の数字、delキー、←→キー、半角キーのみを許可。貼り付け時も数字のみを抽出
        var text_number : string|null;
        var number      : number;
        CONTENT_ELEMENT.addEventListener("input",()=>{
            text_number = this.#__getRawText(CONTENT_ELEMENT);
            if(text_number){
                number = parseInt(text_number);
                if(MIN_NUMBER <= number && number <= MAX_NUMBER){
                    //pass 認められている数値の範囲内です
                }else{

                    if(number === 0){
                        //0だけ残る時は、zero paddingによって 01が0になった場合がある。
                        // その際、最小値にしておく　ver 2.6.3
                        //➡こうすると、最小値からほかの数値に変えるときに下の条件分岐においてalert(範囲外)
                        // が表示された。そのため、ver 2.6.4において、空欄にするように　もとに戻しました。
                        this.#__setValueToContentElement(CONTENT_ELEMENT,"");
                    }else{
                        if(isNaN(number)){
                            //windows + vの貼り付けで文字列を入れるとNaNになる

                        }else{
                            alert(`入力しようとされた数値:${number}は範囲外の数値です。\n値は${MIN_NUMBER}～${MAX_NUMBER}を入力してください。`);
                            this.#__setValueToContentElement(CONTENT_ELEMENT,"");
                        }


                    }
                    this.#__setCursorToEnd(CONTENT_ELEMENT);

                }

            }else{
                //delキーを押すと　何も入ってない場合がある。その時は最小値を入力
                //CONTENT_ELEMENT.textContent = `${MIN_NUMBER}`
            }
        })

    }

    #__withinMonthlyDate(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement, MONTH_ELEMENT : HTMLDivElement|HTMLSpanElement):void{
        this.#__onlyNumbers(CONTENT_ELEMENT);

        CONTENT_ELEMENT.addEventListener("input",()=>{
            var monthString     : string|null = this.#__getRawText(MONTH_ELEMENT);
            if(monthString){
                this.#__validateMonthlyDate(CONTENT_ELEMENT,monthString);
            }else{
                alert(`月を指定してください`);
                this.#__setValueToContentElement(CONTENT_ELEMENT,"");
            };
        })

        MONTH_ELEMENT.addEventListener("input",()=>{
            var monthString     : string|null = this.#__getRawText(MONTH_ELEMENT);
            if(monthString){
                this.#__validateMonthlyDate(CONTENT_ELEMENT,monthString);
            }else{
               //[ここだけ変わっています。月ELEMENTの時にはalert出すと煩わしいので　消去]
            }
        })
    }

    #__validateMonthlyDate(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement,monthString : string)                       :void{
        const CURRENT_YEAR  : number = new Date().getFullYear();
        const CURRENT_MONTH : number = new Date().getMonth();
        var monthNumber     : number = parseInt(monthString);//[ーーーここまでで、入力時のMONTH_ELEMENTから数値を取得し、numberにパースする。]
        var maxDate         : number = 0;   //この二つ　　　　　　　　　　　　　　なるのです。
        var taskYear        : number = 2025;//　　　　なんか入れとかないとエラーに

        if      (monthNumber >= CURRENT_MONTH){//今年の場合
            maxDate     = new Date(CURRENT_YEAR,monthNumber,0).getDate();
            taskYear    = CURRENT_YEAR;
        }else if(monthNumber < CURRENT_MONTH){//来年の場合
            //現在の月よりも、指定された月が若ければ　これは来年を示す。
            // monthNumber:5 , CURRENT_MONTH:4 ➡　今年の５月
            // monthNumber:1 , CURRENT_MONTH:4 ➡　来年の１月
            maxDate     = new Date(CURRENT_YEAR+1,monthNumber,0).getDate();
            taskYear    = CURRENT_YEAR+1;
        }
        //---------------------ここまでで、validationの範囲を獲得しました。

        var dayString       : string|null = this.#__getRawText(CONTENT_ELEMENT);
        var dayNumber       : number;

        if(dayString){

            dayNumber   = parseInt(dayString);
            if(dayNumber){
                if      (0< dayNumber && dayNumber <= maxDate ){
                    //pass　範囲内の数値です
                }else{
                    alert(`入力されたのは${dayNumber}日でしたが、${taskYear}年の${monthNumber}月は${maxDate}日までです。`);
                    this.#__setValueToContentElement(CONTENT_ELEMENT,"");
                }

            }else{// 00日になった時や-であるとき
                if(dayString=="-"){
                    //pass　入力をまつ
                }else{
                    this.#__setValueToContentElement(CONTENT_ELEMENT,"01");
                }
            }

        }else{
            //type scriptなので、しょうがなくやっていますが
            //pass
            //普通ならばね・・・
        }
    }

    /**
     * @abstract 思いつく限り、最高２桁した０埋めは必要ないかと思うので、現状1を01にするってかんじ。
     */
    #__zeroPadding(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement)                                                     : void{
        CONTENT_ELEMENT.addEventListener("input",()=>{
            var text_number : string|null = this.#__getRawText(CONTENT_ELEMENT);
            if(text_number){
                //[Fix Me] : 00にした後、1~9を入力すると 01~09ではなく、1~9と入力される。

                const IS_NUMBER : boolean = text_number.match(/^[0-9]+$/) ? true: false;
                //文字列の頭(^)から終わり($)まで数字で構成されていたらtrue

                if(text_number.length === 1 && IS_NUMBER){
                    text_number = `0${text_number}`;
                    this.#__setValueToContentElement(CONTENT_ELEMENT,text_number);
                }

                const HEAD_NUMBER : string = text_number.charAt(0);
                if(HEAD_NUMBER==="0" && text_number.length > 2){
                    this.#__setValueToContentElement(CONTENT_ELEMENT, text_number.replace(/^0/, ""));
                    /*例　text_number :
                        001 → 01
                        011 → 11
                        頭の0を一つだけ削除する
                    */
                }

                this.#__setCursorToEnd(CONTENT_ELEMENT);
            }
        })
    }

    #__renderWeekday(CONTENT_ELEMENT : HTMLDivElement|HTMLSpanElement|HTMLInputElement, MONTH_ELEMENT : HTMLDivElement|HTMLSpanElement, DATE_ELEMENT : HTMLDivElement|HTMLSpanElement)  : void{
        MONTH_ELEMENT.addEventListener("input",()=>{
            const MONTH_STRING      : string|null = this.#__getRawText(MONTH_ELEMENT);
            const DATE_STRING       : string|null = this.#__getRawText(DATE_ELEMENT);
            if(MONTH_STRING && DATE_STRING){
                const MONTH_NUMBER  : number = parseInt(MONTH_STRING);
                const DATE_NUMBER   : number = parseInt(DATE_STRING);

                if(MONTH_NUMBER >= 0 && DATE_NUMBER >=0){
                    const WEEKDAY = this.UtilsFunc.calcWeekday(MONTH_NUMBER,DATE_NUMBER);
                    this.#__setValueToContentElement(CONTENT_ELEMENT,`(${WEEKDAY})`);
                }else{
                    this.#__setValueToContentElement(CONTENT_ELEMENT,`()`);
                }

            }else{
                this.#__setValueToContentElement(CONTENT_ELEMENT,`()`);
            }


        })

        DATE_ELEMENT.addEventListener("input",()=>{
            const MONTH_STRING      : string|null = this.#__getRawText(MONTH_ELEMENT);
            const DATE_STRING       : string|null = this.#__getRawText(DATE_ELEMENT);
            if(MONTH_STRING && DATE_STRING){
                const MONTH_NUMBER  : number = parseInt(MONTH_STRING);
                const DATE_NUMBER   : number = parseInt(DATE_STRING);

                if(MONTH_NUMBER >= 0 && DATE_NUMBER >=0){
                    const WEEKDAY = this.UtilsFunc.calcWeekday(MONTH_NUMBER,DATE_NUMBER);
                    this.#__setValueToContentElement(CONTENT_ELEMENT,`(${WEEKDAY})`);
                }else{
                    this.#__setValueToContentElement(CONTENT_ELEMENT,`()`);
                }

            }else{
                this.#__setValueToContentElement(CONTENT_ELEMENT,`()`);
            }

        })
    }

    #__isLaunchEvent(VALIDATETION_NAME : string)                                                                         : boolean|void{
        const CURRENT_TIME       = new Date();
        if(VALIDATETION_NAME==="onlyNumbers"){
            const LAST_LAUNCHED_TIME    = this.lastLaunchTimes.onlyNumbers;
            const TIME_LAPSE   : number = CURRENT_TIME.getTime() - LAST_LAUNCHED_TIME.getTime();
            return  TIME_LAPSE >= this.debounceTime ? true : false ;
        }else{
            alert(`現在、追加されてないvalidation nameです: ${VALIDATETION_NAME}`)
        }
    }

    /**
     * @description 現状、二つのエレメントはSPANかつ、どちらも同じpositionオプションを設定されてなければなりません。
     * @param TARGET_SPAN
     * @param REF_SPAN
     */
    alignSpanToAdjacentInputCenter(TARGET_SPAN : HTMLSpanElement, INPUT_SPAN : HTMLSpanElement){
        const TARGET_SPAN_STYLE     : CSSStyleDeclaration = window.getComputedStyle(TARGET_SPAN);
        const FIRST_TARGET_SPAN_TOP : string              = TARGET_SPAN_STYLE.top;

        INPUT_SPAN.addEventListener("input",()=>{
            const INPUT_SPAN_STYLE  : any                 = window.getComputedStyle(INPUT_SPAN);

            const INPUT_FONT_SIZE   : number              = parseInt(INPUT_SPAN_STYLE.fontSize);
            const BASED_LINE_HEIGHT : number              = Math.round(1.485*INPUT_FONT_SIZE + 0.587);
            const LINE_HEIGHT       : number              = INPUT_FONT_SIZE * 0.7;
            const INPUT_SPAN_HEIGHT : number              = INPUT_SPAN_STYLE.height.replace("px","");
            const LINES             : number              = Math.round(INPUT_SPAN_HEIGHT/BASED_LINE_HEIGHT);

            TARGET_SPAN.style.top = FIRST_TARGET_SPAN_TOP;
            //<XXX> :　マジックナンバーを使っています。font-size=35の時しか作動しない可能性があります。だが、私は修正しない！
            TARGET_SPAN.style.top = `${parseInt(TARGET_SPAN_STYLE.top.replace("px","")) - LINE_HEIGHT*LINES + parseInt(FIRST_TARGET_SPAN_TOP.replace("px",""))*2-13}px`;

        })
    }

    provideUniqueID(){
        const DATE_RND_ID : string = `${Date.now().toString(36)}-${Math.random().toString(36).substring(2,8).padEnd(6,"0")}`
        const CRYPTO_ID    : string = crypto.getRandomValues(new Uint32Array(1))[0].toString(16).padStart(8,"0");
        const MIXED_ID    : string = `${DATE_RND_ID}-${CRYPTO_ID}`

        return MIXED_ID
    }

    /**
     * @description 同じHtmlImageElementでsrcパスのみを変えて使いまわす際のツールです。
     * @param IMAGE_ELEMENT
     * @param NEW_IMAGE_SRC
     */
    changeImage(IMAGE_ELEMENT : HTMLImageElement, NEW_IMAGE_SRC : string) : void{
        const PARENT_PATH   : string  = IMAGE_ELEMENT.src.substring(0, IMAGE_ELEMENT.src.lastIndexOf("/")+1);
        const NEW_FULL_PATH : string = `${PARENT_PATH}${NEW_IMAGE_SRC}`;
        IMAGE_ELEMENT.src = NEW_FULL_PATH;
    }
}

/**
 * @description HTMLElementにアニメーションを簡単につけられます。
 * @version 1.0.0
 * @abstract fade in , fade outが選択できます。
 *
 */
class AnimateFunctions{
    constructor(){
        console.log("ヒント：アニメをつけるElementはdisplay:noneに設定していてください。")
    }

    /**
     * @abstract フェードスピードの初期値は0.05です。
     * @param {*} ELEMENT
     * @param {*} SPEED
     */
    fadeIn(ELEMENT : HTMLDivElement, SPEED : number =0.05) : void{
        var opacity : number  = 0;//透明度
        ELEMENT.style.opacity = opacity.toString();
        //TypeScriptでは、HTML-Element.style.は文字列として扱われるらしい。
        //なので、opacity : numberは文字列に直す。
        ELEMENT.style.display = "block";

        const FADE_EFFECT : any = setInterval( () =>{

                                                if(opacity < 1){//非　透明でなければ
                                                    opacity += SPEED;
                                                    ELEMENT.style.opacity = opacity.toString();
                                                }else{
                                                    clearInterval(FADE_EFFECT);
                                                }

                                               }, 50);//0050ms秒ごとに実行
    }

    /**
     * @abstract フェードスピードの初期値は0.05です。
     * @param {*} ELEMENT
     * @param {*} SPEED
     */
    fadeOut(ELEMENT : HTMLDivElement ,SPEED : number=0.05) : void{
        var opacity : number = 1;//透明度
        const FADE_EFFECT : any = setInterval( () =>{

                                                if(opacity > 0){//完全に透明でなければ
                                                    opacity -= SPEED;
                                                    ELEMENT.style.opacity = opacity.toString();
                                                }else{
                                                    clearInterval(FADE_EFFECT);
                                                    ELEMENT.style.display = "none";
                                                }

                                               }, 50);//0050ms秒ごとに実行
    }
}

type CharWaterflowOptions = {
    BACKGROUND_COLOR?: string;
    ANIMATE_COLOR_PATTERN?: string[];
    BASIC_FONT_COLOR?: string;
};
type BoundBallsOptions = {
    BACKGROUND_COLOR?   : string;
    FONT_COLOR?         : string;
    LEFT_PX?            : string;
    DISPLAY_CONTENT?    : string;
};
const CLOSE_SYSTEM     = ["SleepTimerMode","SelfTimerMonitoringMode","BroadcastMonitoringMode","SelfCloseMode"] as const;
type closeSystemType   = typeof CLOSE_SYSTEM[number];


/**
 * @description firebaseからデータを取得する際など、非同期処理を待つ間に表示する
 * preloader画面を簡単に作成します。
 * 現在は選択可能な種類は2種類のみ。
 * もしほかのアニメーションを追加したい場合、こちらを参考にしましょう。
 * 追加したらば、UtilsFunctionsのsleepで使うoption追加してね！！
 * https://photopizza.design/css_loading/
 * @version 2.3.0
 *
 * @abstract
 * ```
 * version 1.0.0  charWaterflowを導入
 *           1.0  boundBallsを導入
 *            .1  z-indexが99では最前面にならない場合があり、
 * 　　　　　　　　 999999999999999999999とした。
 *         2.0.0  FirebaseFunctionsを利用して、preloaderの表示時間を正確に計測できるようにしました。
 *                これに伴い、sleepによる非表示処理は中止しました。
 *                以前のsleep関数ではすべての処理が停止し、背面において画像のサイズ変更処理等をしたくとも
 * 　　　　　　　　 sleepが終わるまで処理が進まないバグがありました。
 * 　　　　　　　　 今回のアップデートによって、内部処理を停止することなくloadingすることが可能になりました。
 *           (a)  sendStartTimeToFirebase関数を導入。（preloading開始時刻の送信）
 *           (b)  startAutoCloseMonitor関数を導入。preloadingを自動的に閉じる監視システムです。
 *           (c)  isTimeToClosePreloader関数を導入。
 * 　　　　　 (d)  closePreLoader関数において、sleepの記述を削除しました。
 *           (e)  commonPreloadingSetup関数を導入。preloadingの共通セットアップをまとめました。
 *         2.0.1  <xxx>FirebaseFunctions内でPreloaderを使用しているdecryptDataにおいて、無限にFirebaseFunctionsを生成する致命的なバグが見つかりました。
 *         2.1.0  以前のsleep式の方法も利便性があり、FirebaseFunctionsを無限生成するバグを回避できるため
 * 　　　　　　　　 2つのモード["SleepTimerMode","MonitoringMode"]を選べるようにしました。
 *                SleepTimerModeはver1.0.0のsleepを使用したpreloaderの閉じ方です。
 * 　　　　　　　  MonitoringModeはver2.0.0からのFirebase RealtimeDatabaseを使用したpreloaderの閉じ方です。
 * 　　　　　　(a) sendStartTimeToFirebase関数をsendStartSignalToFirebaseと改名し、仕組みを修正。
 *            (b) isHaveFirebaseApp関数を追加。
 *            (c) commonPreloadingSetup関数を修正。
 *            (d) isTimeToClosePreloader関数をisReadyToClosePreloaderとし、仕組みを修正。
 * 　　　　　　(e) charWaterflow,boudBallsの引数の仕組み、並びを変更。
 * 　　　　 2.2.0  Firebaseを使用するものは、複数ユーザーの画面を一括してpreloaderするための仕組みとして使えることがわかりました。
 *                これをMonitoringModeからBroadcastMonitoringModeと改名しました。
 * 　　　　　　　　 一方、時間を設定してクラス内部でpreloaderの時間内のみ開くモード SelfTimerMonitoringModeを追加。
 * 　　　　 2.3.0  手動で開始し、手動で閉じるSelfCloseModeを追加。
 *
 * ```
 */

class PreLoader{
    PRELOADER_MODAL     : HTMLDivElement;
    STYLE               : HTMLStyleElement;

    constructor(){

        // 1. プリローダーHTMLを追加
        this.PRELOADER_MODAL = document.createElement("div");
        this.PRELOADER_MODAL.className = "preloader";

        this.STYLE = document.createElement("style");

    }


    /**
     * @abstract 滝のようにLOADTINGの文字が流れます
     * @description BACKGROUND_COLORでモダールの背景色を指定
     * ANIMATE_COLOR_PATTERNはリスト型に３色の色を指定。アニメ指定した文字色になる
     * BASIC_FONT_COLORで非アニメ指定文字の色を指定
     */
    charWaterflow(CLOSE_SYSTEM_TYPE : closeSystemType, FIREBASE_APP : FirebaseFunctions|null = null,PRELOADING_TIME_MS : number = 0,{
        BACKGROUND_COLOR       = `rgba(0, 0, 0, 0.8)`,
        ANIMATE_COLOR_PATTERN  =  [`#0088cc`,`#e23069`,`#F0E300`],
        BASIC_FONT_COLOR = `rgb(255, 255, 255)`
    } : CharWaterflowOptions ={}){

        document.body.prepend(this.PRELOADER_MODAL);

        //1. HTMLを追加
        this.PRELOADER_MODAL.innerHTML = `
            <img src="labo-logo.png" class="labo-logo" id="labo-logo">
            <div class="loading">
                <span>L</span>
                <span class="animate">O</span>
                <span class="animate">A</span>
                <span class="animate">D</span>
                <span>I</span>
                <span>N</span>
                <span>G</span>
            </div>
        `;

        //２. CSSを追加
        var   basicStyleContext =  `
        .preloader {
            position: fixed;
            top: 0px;
            background-color: ${BACKGROUND_COLOR};
            width: 100%;
            height: 100%;
            z-index: 999999999999999999999;
        }
        .labo-logo {
            position: relative;
            top: 30%;
            margin: auto;
            display: block;
            width: auto;
        }
        @keyframes spin {
            0% { top: 0; }
            50% { top: 100%; opacity: 0; }
            51% { top: -100%; }
            100% { top: 0; opacity: 1; }
        }

        .loading {
            position: relative;
            top: 32%;
            width: 100%;
            text-align: center;
          }

          .loading span {
            color: ${BASIC_FONT_COLOR};
            font-size: 30px;
          }

          .loading .animate {
            position: absolute;
            top: 0;
          }
        `;
        var   animateStyleContext = `
            .loading span:nth-child(2) {
                color: ${ANIMATE_COLOR_PATTERN[0]};
                animation: spin 1.5s linear infinite;
                -webkit-animation: spin 1.5s linear infinite;
            }

            .loading span:nth-child(3) {
                margin-left: 25px;
                color: ${ANIMATE_COLOR_PATTERN[1]};
                animation: spin 1s linear infinite;
                -webkit-animation: spin 1s linear infinite;
            }

            .loading span:nth-child(4) {
                margin-left: 50px;
                color:${ANIMATE_COLOR_PATTERN[2]};
                animation: spin 1.25s linear infinite;
                -webkit-animation: spin 1.25s linear infinite;
            }

            .loading span:nth-child(5) {
                padding-left: 77px;
            }
        `;
        this.STYLE.textContent = basicStyleContext + animateStyleContext;
        document.head.appendChild(this.STYLE);

        this.commonPreloadingSetup(CLOSE_SYSTEM_TYPE, FIREBASE_APP,PRELOADING_TIME_MS);
    }

    /**
     * @abstract ボールがぷよぷよ　飛び跳ねます
     * @description
     * BACKGROUND_COLORでモダールの背景色を指定（デフォルト：黒＋透明度0.8）
     * FONT_COLORで文字色を指定（デフォルト：白）
     * DISPLAY_CONTENTで表示する文字を指定（デフォルト：" "）
     * LEFT_PXは表示する文字位置を調整(デフォルト：0px)
     *
     */
    boundBalls(CLOSE_SYSTEM_TYPE : closeSystemType, FIREBASE_APP : FirebaseFunctions|null = null,PRELOADING_TIME_MS : number = 0,{
        BACKGROUND_COLOR    = `rgba(0, 0, 0, 0.8)`,
        FONT_COLOR          = `rgb(255, 255, 255)`,
        LEFT_PX             = "0px",
        DISPLAY_CONTENT     = ""
    } : BoundBallsOptions ={}){

        document.body.prepend(this.PRELOADER_MODAL);

        //1. HTMLを追加
        this.PRELOADER_MODAL.innerHTML = `

            <img src="labo-logo.png" class="labo-logo" id="labo-logo">
            <div class="loading">
                <div class="wrapper">
                <div class="circle"></div>
                <div class="circle"></div>
                <div class="circle"></div>
                <div class="shadow"></div>
                <div class="shadow"></div>
                <div class="shadow"></div>
            </div>
            <div class="exp">${DISPLAY_CONTENT}</div>
        `;

        //２. CSSを追加
        var   basicStyleContext =  `
                                    .labo-logo {
                                        position: relative;
                                        top: 30%;
                                        margin: auto;
                                        display: block;
                                        width: auto;
                                    }
                                    .loading {
                                        position: relative;
                                        top: 32%;
                                        width: 100%;
                                        text-align: center;
                                    }

                                    .loading span {
                                        color: rgb(0,0,0);
                                        font-size: 30px;
                                    }

                                    .loading .animate {
                                        position: absolute;
                                        top: 0;
                                    }
                                    .preloader {
                                        position: fixed;
                                        top: 0px;
                                        background-color: ${BACKGROUND_COLOR};
                                        width: 100%;
                                        height: 100%;
                                        z-index: 999999999999999999999;
                                    }
                                    body{
                                        padding:0;
                                        margin:0;
                                        width:100%;
                                        height:100%;

                                    }
                                    .wrapper{
                                        width:200px;
                                        height:60px;
                                        position: absolute;
                                        left:50%;
                                        top:50%;
                                        transform: translate(-50%, -50%);
                                    }
                                    .circle{
                                        width:20px;
                                        height:20px;
                                        position: absolute;
                                        border-radius: 50%;
                                        background-color: #e1f3e1ff;
                                        left:15%;
                                        transform-origin: 50%;
                                        animation: circle .5s alternate infinite ease;
                                    }

                                    @keyframes circle{
                                        0%{
                                            top:100px;
                                            height:5px;
                                            border-radius: 50px 50px 25px 25px;
                                            transform: scaleX(1.7);
                                        }
                                        40%{
                                            height:20px;
                                            border-radius: 50%;
                                            transform: scaleX(1);
                                        }
                                        100%{
                                            top:0%;
                                        }
                                    }
                                    .circle:nth-child(2){
                                        left:45%;
                                        animation-delay: .2s;
                                    }
                                    .circle:nth-child(3){
                                        left:auto;
                                        right:15%;
                                        animation-delay: .3s;
                                    }
                                    .shadow{
                                        width:20px;
                                        height:4px;
                                        border-radius: 50%;
                                        background-color: rgba(0,0,0,.5);
                                        position: absolute;
                                        top:102px;
                                        transform-origin: 50%;
                                        z-index: -1;
                                        left:15%;
                                        filter: blur(1px);
                                        animation: shadow .5s alternate infinite ease;
                                    }

                                    @keyframes shadow{
                                        0%{
                                            transform: scaleX(1.5);
                                        }
                                        40%{
                                            transform: scaleX(1);
                                            opacity: .7;
                                        }
                                        100%{
                                            transform: scaleX(.2);
                                            opacity: .4;
                                        }
                                    }
                                    .shadow:nth-child(4){
                                        left: 45%;
                                        animation-delay: .2s
                                    }
                                    .shadow:nth-child(5){
                                        left:auto;
                                        right:15%;
                                        animation-delay: .3s;
                                    }

                                    .exp{
                                        position    : relative;
                                        top         : 150px;
                                        left        : ${LEFT_PX};
                                        color       : ${FONT_COLOR};
                                        font-size   : 35px;
                                    }


        `;

        this.STYLE.textContent = basicStyleContext;
        document.head.appendChild(this.STYLE);

        this.commonPreloadingSetup(CLOSE_SYSTEM_TYPE, FIREBASE_APP,PRELOADING_TIME_MS);
    }

    async commonPreloadingSetup(CLOSE_SYSTEM_TYPE : closeSystemType, FIREBASE_APP : FirebaseFunctions|null=null,PRELOADING_TIME_MS : number){

        if(CLOSE_SYSTEM_TYPE === "BroadcastMonitoringMode"){
            if(this.#isHaveFirebaseApp(FIREBASE_APP)){

            }else{
                console.log("in Preloader, mode is Monitor, but you didn't set FirebaseFunctions instance. So, Preloader can't monitor preloading time correctly.");
            }

            this.#sendStartSignalToFirebase(FIREBASE_APP!);
            this.#startAutoCloseBroadcastMonitor(FIREBASE_APP!);
        }else if(CLOSE_SYSTEM_TYPE === "SleepTimerMode"){
            //no process
        }else if(CLOSE_SYSTEM_TYPE === "SelfTimerMonitoringMode"){
            const START_TIME  = Date.now();
            this.#startAutoCloseSelfTimerMonitor(START_TIME,PRELOADING_TIME_MS);
        }else if(CLOSE_SYSTEM_TYPE === "SelfCloseMode"){
            // nothing
        }

    }

    // ===================================
    // == SelfTimerMonitoringModeの関数 ==
    // ===================================
    #startAutoCloseSelfTimerMonitor(START_TIME : number,PRELOADING_TIME_MS : number){
        const timerId = setInterval( async () => {
            const CAN_BE_CLOSED =  this.#isReadyToCloseSelfTimerPreloader(START_TIME,PRELOADING_TIME_MS!);

            if(CAN_BE_CLOSED){
                console.log("close")
                clearInterval(timerId);
                await this.closePreLoader("BroadcastMonitoringMode");
            }

        }, 500);
    }
    #isReadyToCloseSelfTimerPreloader(START_TIME : number,PRELOADING_TIME_MS:number) : boolean{
        console.log(`time lapse is  ${Date.now()- START_TIME}, Start time is ${START_TIME},and preloading time is ${PRELOADING_TIME_MS}`)
        return Date.now() - START_TIME > PRELOADING_TIME_MS ? true : false ;
    }


    // ===================================
    // == BroadcastMonitoringModeの関数 ==
    // ===================================
    #isHaveFirebaseApp(FIREBASE_APP: FirebaseFunctions|null){
        return FIREBASE_APP ? true : false ;
    }
    #sendStartSignalToFirebase(FIREBASE_APP : FirebaseFunctions){
        // await this.deleteOldDataSystem(FIREBASE_APP);
        // //lastSendTimeを評価します。その後に最新のlastSendTimeを送信します。

        FIREBASE_APP.uploadData(`PreLoader/status`,"preparing")
        // FIREBASE_APP.uploadData(`PreLoader/lastSendTime`,Date.now());
    }
    #startAutoCloseBroadcastMonitor(FIREBASE_APP : FirebaseFunctions){
        const timerId = setInterval( async () => {
            const CAN_BE_CLOSED = await this.#isReadyToCloseBroadcastPreloader(FIREBASE_APP!);
            if(CAN_BE_CLOSED){
                clearInterval(timerId);
                await this.closePreLoader("BroadcastMonitoringMode");
            }

        }, 500);
    }
    async #isReadyToCloseBroadcastPreloader(FIREBASE_APP : FirebaseFunctions) : Promise<boolean>{
        const STATUS = await FIREBASE_APP.downloadData(`PreLoader/status`);
        return STATUS === "readyToClose" ? true : false;
    }

    sendEndSignalToFirebase(FIREBASE_APP : FirebaseFunctions){
        FIREBASE_APP.uploadData(`PreLoader/status`,"readyToClose");
    }

    // async deleteOldDataSystem(FIREBASE_APP : FirebaseFunctions){
    //     const LAST_SEND_TIME =  await FIREBASE_APP.downloadData(`PreLoader/lastSendTime`);
    //     const CURRENT_TIME   = Date.now();
    //     const TIME_LAPSE_MS  = CURRENT_TIME - LAST_SEND_TIME;
    //     const ONE_HOUR_MS    = 1000 * 60 * 60;

    //     if(TIME_LAPSE_MS > ONE_HOUR_MS){
    //         FIREBASE_APP.deleteData("PreLoader/statuses");
    //     }
    // }

    async closePreLoader(CLOSE_SYSTEM_TYPE : closeSystemType){
        const AnimateFunc = new AnimateFunctions();
        const UtilsFunc   = new UtilsFunctions();

        AnimateFunc.fadeOut(this.PRELOADER_MODAL);

        if      (CLOSE_SYSTEM_TYPE === "BroadcastMonitoringMode"){
            this.PRELOADER_MODAL.remove();
            this.STYLE.remove();

        }else if(CLOSE_SYSTEM_TYPE === "SleepTimerMode"){
            await UtilsFunc.sleep(1000,null);
            this.PRELOADER_MODAL.remove();
            this.STYLE.remove();

        }else if(CLOSE_SYSTEM_TYPE === "SelfTimerMonitoringMode"){
            this.PRELOADER_MODAL.remove();
            this.STYLE.remove();

        }else if(CLOSE_SYSTEM_TYPE === "SelfCloseMode"){
            this.PRELOADER_MODAL.remove();
            this.STYLE.remove();
        }
    }


}


const CONFIG =  {
    apiKey: "AIzaSyC04Rv-MGUkB4nUve3-_7XA_p6HHQrheFs",
    authDomain: "mapannounce.firebaseapp.com",
    projectId: "mapannounce",
    storageBucket: "mapannounce.firebasestorage.app",
    messagingSenderId: "730228875368",
    appId: "1:730228875368:web:0d4f7298ca10c219c95bdd",
    measurementId: "G-VTKN7RZ6XT"
};
const FIREBASE_FUNCTION = new FirebaseFunctions(CONFIG,false);


interface LocationData {
    label: string;  // 「げんざい」「ひだり」「みぎ」など
    name: string;
    pref: string;
    city: string;
    type: "CURRENT" | "LEFT" | "RIGHT";
}

interface AnnounceGroup extends LocationData {
    directionTitle: string;
    repeat?: boolean;
}
class App{
    CURRENT_GEO_DATA!       : object;
    RIGHT_GEO_DATA!         : object;
    LEFT_GEO_DATA!          : object;

    CURRENT_POINT!          : any;
    LEFT_POINT!             : any;
    RIGHT_POINT!            : any;

    currentKoazaOoaza!      : string;
    leftKoazaOoaza!         : string;
    rightKoazaOoaza!        : string;

    previousKoaza!          : Record<string,string>;

    current_cityName!       : string;
    left_cityName!          : string;
    right_cityName!         : string;

    previousCityName!       : Record<string,string>;


    current_prefName!       : string;
    left_prefName!          : string;
    right_prefName!         : string;

    previousPrefName!       : Record<string,string>;

    lastLaunchTime__loadWaypointGeoJSON_Data!   : number;
    APP_START_TIME          : number;

    lastLongitude!          : number;
    lastLatitude!           : number;

    FIREBASE_FUNCTION       : FirebaseFunctions;

    debug_fetchCounter                     : number;

    intervalID!             : any;

    constructor(FIREBASE_FUNCTION : FirebaseFunctions){
        this.FIREBASE_FUNCTION                  = FIREBASE_FUNCTION;
        this.APP_START_TIME                     = Date.now();              //履歴情報に使用します。　=>sendHistoryLogToFirebasesendHistoryLogToFirebase()


        this.debug_fetchCounter                 = 0;                       //debug用カウンター。　=>getCityCode()
        this.lastLaunchTime__loadWaypointGeoJSON_Data = Date.now() - 60*60*1000; //初期値は１分前に設定。

        this.lastLatitude                       = 0;
        this.lastLongitude                      = 0;

        // Recordの初期化（各キーを空文字で埋める）
        this.previousKoaza                      = { CURRENT: "", LEFT: "", RIGHT: "" };
        this.previousCityName                   = { CURRENT: "", LEFT: "", RIGHT: "" };
        this.previousPrefName                   = { CURRENT: "", LEFT: "", RIGHT: "" };

        this.init();
    }

    async init(){

        await this.naviMainSystem();

        //=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=
        this.setupSettingEffect();

        await this.loadUserParameterAndInput();

        this.intervalSystem();

        this.attachEvent();  
    }



    async naviMainSystem(){
        navigator.geolocation.getCurrentPosition(async (position) => { // fetchCurrentPosition.  非同期関数のため、関数内にすべての処理を入れる必要があります。
            // 現在取得した座標の変数名を改名。
            var { longitude, latitude } = position.coords;
            const CURRENT_LONGITUDE     = longitude;
            const CURRENT_LATITUDE      = latitude;


            // 移動距離チェック
            if (!this.hasMovedEnough(CURRENT_LATITUDE, CURRENT_LONGITUDE)) {
                return; // 5m以上動いていなければここで終了

            }else{
                this.GPS_AccuracySystem(position); 
                // GPSの精度を評価し、表示を更新します。精度が悪い場合は処理を中断します。
                
                const EACH_SIDE_COORD_RECORD = this.produceEachSideCoordRecord(CURRENT_LONGITUDE,CURRENT_LATITUDE);
                //左右方面地点の座標レコードを生成

                this.waypointCoordsCalcSystem(CURRENT_LONGITUDE,CURRENT_LATITUDE,EACH_SIDE_COORD_RECORD);
                //現在地点、右方面地点、左方面地点の座標をglobal変数　
                //this.CURRENT_POINT, .RIGHT_POINT, .LEFT_POINTに保存する。

                this.loadCityDataSystem(CURRENT_LATITUDE,CURRENT_LONGITUDE,EACH_SIDE_COORD_RECORD);

                this.Announce();
                
                if(this.lastLongitude == 0 && this.lastLatitude == 0){
                    //初回起動時は実行しません。
                }else{
                    this.playInNewCitySound();
                }

                //====================== Display Update System===============================
                //===========================================================================
                // 履歴の更新
                this.addHistoryLog();

                this.updatePreviousePlaceNames();     

                this.DisplayInfo();
            }
        

            // 前回の座標を更新
            this.lastLongitude = CURRENT_LONGITUDE;
            this.lastLatitude  = CURRENT_LATITUDE;

        }, (error) => {
        console.error("位置情報の取得に失敗しました", error);
        }, {
            enableHighAccuracy: true, // 高精度モードを有効化
            timeout: 5000,
            maximumAge: 0
        });
    }

    //============== Essential judge function  ==================
    //===========================================================
    private hasMovedEnough(currentLat: number, currentLng: number): boolean {
        // 初回（前回の座標がない場合）は移動したとみなして実行
        if (this.lastLatitude === 0 && this.lastLongitude === 0) return true;

        const from                  = turf.point([this.lastLongitude, this.lastLatitude]);
        const to                    = turf.point([currentLng, currentLat]);
        
        // 距離を計算（単位：meters）
        const distance              = turf.distance(from, to, { units: 'meters' });

        // 閾値を設定（ここでは5mとしていますが、適宜調整してください）
        const MOVEMENT_THRESHOLD    = 5; 

        if (distance < MOVEMENT_THRESHOLD) {
            console.log(`移動距離が不十分なためスキップ: ${distance.toFixed(2)}m`);
            return false;
        }else{
            console.log(`移動検知: ${distance.toFixed(2)}m`);
            return true;
        }

    }

    //==============GPS System functions ========================
    //===========================================================
    GPS_AccuracySystem(position: GeolocationPosition) : void{
        this.updateGPS_AccuracyDisplay(position);
            
        if(this.isReliableGPS_Accuracy(position)){
            // skip
        }else{
            return //処理を中断。信用ならないGPSは除外
        }
    }
    private updateGPS_AccuracyDisplay(position : any) : void{
        const GPS_STATUS            = document.getElementById("gps-status")       as HTMLDivElement;
        
        const ACCURACY_RATIO = this.calcAccuracyRatio(position);

        // --- 精度によるステータス表示の切り替え ---
        if (ACCURACY_RATIO <= 0.3) {
            // かなり正確（青〜緑）
            GPS_STATUS.innerText = "高精度";
            GPS_STATUS.style.backgroundColor = "var(--accent)"; // 緑
        } else if (ACCURACY_RATIO <= 0.7) {
            // 普通（緑〜黄色）
            GPS_STATUS.innerText = "中精度";
            GPS_STATUS.style.backgroundColor = "#AFCE33"; // 黄緑
        } else if (ACCURACY_RATIO <= 1.0) {
            // 境界線（黄色）
            GPS_STATUS.innerText = "低精度";
            GPS_STATUS.style.backgroundColor = "#FFD60A"; // 黄
            GPS_STATUS.style.color = "black";
        } else {
            // 閾値を超えた（オレンジ〜赤）
            GPS_STATUS.innerText = "精度不足";
            GPS_STATUS.style.backgroundColor = "#FF3B30"; // 赤
            GPS_STATUS.style.color = "white";
        }
    }
    private calcAccuracyRatio(position:any)           : number{
        const ACCURACY_DISPLAY      = document.getElementById("accuracy-display") as HTMLDivElement;
        const THRESHOLD_INPUT       = document.getElementById("threshold-input")  as HTMLInputElement;

        const ACCURACY              = Math.round(position.coords.accuracy);
        const ACCURACY_THRESHOLD    = parseInt(THRESHOLD_INPUT.value) || 100;
        ACCURACY_DISPLAY.innerText  = `GPS誤差 : ${ACCURACY}m`;
        const ACCURACY_RATIO = ACCURACY / ACCURACY_THRESHOLD;

        return ACCURACY_RATIO;
    }

    private isReliableGPS_Accuracy(position : any)    : boolean{
        const THRESHOLD_INPUT       = document.getElementById("threshold-input") as HTMLInputElement;//閾値
        const ACCURACY_THRESHOLD    = parseInt(THRESHOLD_INPUT.value) || 100;  

        const ACCURACY              = position.coords.accuracy; // 単位：メートル     

        if (ACCURACY > ACCURACY_THRESHOLD) {
            console.warn(`GPS精度不足のためスキップ: 誤差 ${Math.round(ACCURACY)}m`);
            return false;
        }else{
            return true
        }
    }
    //=================================================================


    //============== calculate waypoint coord system =====================
    //=====================================================================
    waypointCoordsCalcSystem(CURRENT_LONGITUDE : number,CURRENT_LATITUDE : number, EACH_SIDE_POINT_RECORD : Record<string,Record<string,number>>) : void{
        //========================EachWayPoint Calculation System==============================
        //========================================================================================


        // 経度0.000033、緯度0.000027は３ｍ分になる。
        this.CURRENT_POINT              = turf.point([CURRENT_LONGITUDE, CURRENT_LATITUDE]);
        this.LEFT_POINT                 = turf.point([EACH_SIDE_POINT_RECORD.LEFT_POINT.lng,EACH_SIDE_POINT_RECORD.LEFT_POINT.lat]);
        this.RIGHT_POINT                = turf.point([EACH_SIDE_POINT_RECORD.RIGHT_POINT.lng,EACH_SIDE_POINT_RECORD.RIGHT_POINT.lat]);
    }
    produceEachSideCoordRecord(CURRENT_LONGITUDE : number,CURRENT_LATITUDE : number) : Record<string,Record<string,number>>{
                // 左右の方向を計算・取得
        const DIRECTION_RECORD          = this.calcDirectionSystem(     CURRENT_LATITUDE,   // 緯度を先に
                                                                        CURRENT_LONGITUDE,  // 経度を後に
                                                                        this.lastLatitude,  // 緯度
                                                                        this.lastLongitude  // 経度
                                                                    );
        // 現在地からDISTANCE（ｍ）分離れた左右地点の座標を取得
        const DISTANCE_INPUT            = document.getElementById("distance-input") as HTMLInputElement;
        const OFFSET_DISTANCE           = parseInt(DISTANCE_INPUT.value) || 100;
        const EACH_SIDE_POINT_RECORD    = this.calcEachSidePoint(CURRENT_LATITUDE,CURRENT_LONGITUDE,DIRECTION_RECORD,OFFSET_DISTANCE);
        return EACH_SIDE_POINT_RECORD;                                                          
    }
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    private calcDirectionSystem(CURRENT_LATITUDE: number,CURRENT_LONGITUDE : number,LAST_LATITUDE: number, LAST_LONGITUDE: number){
            // 方位角を計算
            // 北 = 0°, 東 = 90°, 南 = 180°, 西 = 270°
            const NORMAL_DIRECTION           = this.calcNormalDirection(CURRENT_LATITUDE,CURRENT_LONGITUDE,LAST_LATITUDE,LAST_LONGITUDE);
            console.log(`it is direction [${NORMAL_DIRECTION}]`)
            // 現在地点の左右方向を計算
            const EACH_SIDE_DIRECTION_RECORD = this.calcEachSideDirection(NORMAL_DIRECTION);

            return EACH_SIDE_DIRECTION_RECORD;
    }
    private calcNormalDirection(CURRENT_LATITUDE: number,CURRENT_LONGITUDE : number,LAST_LATITUDE: number, LAST_LONGITUDE: number){
        // 前回の位置と今回の位置をもとに、進行方向の方角を計算する。

        const TO_RAD = d => d * Math.PI / 180;
        const TO_DEG = r => r * 180 / Math.PI;

        const Φ1     = TO_RAD(LAST_LATITUDE);
        const Φ2     = TO_RAD(CURRENT_LATITUDE);
        const Δλ     = TO_RAD(CURRENT_LONGITUDE - LAST_LONGITUDE);

        const y      = Math.sin(Δλ) * Math.cos(Φ2);
        const x      = Math.cos(Φ1) * Math.sin(Φ2) - Math.sin(Φ1) * Math.cos(Φ2) * Math.cos(Δλ);

        return (TO_DEG(Math.atan2(y,x)) + 360) % 360;
    }
    private calcEachSideDirection(NORMAL_DIRECTION : number) : Record<string,number>{
        return {
                // 360度を超えたりマイナスになったりしないよう剰余演算
                rightDir: (NORMAL_DIRECTION + 90) % 360,
                leftDir: (NORMAL_DIRECTION - 90 + 360) % 360
            };
    }
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    private WGS84_offsetPosition(CURRENT_LATITUDE : number, CURRENT_LONGITUDE : number, DIRECTION : number, DISTANCE : number){
        //World Geodetic System 1984    
        const EARTH_RADIUS : number = 6378137; // 地球半径（m）


        const TO_RAD = d => d * Math.PI / 180;
        const TO_DEG = r => r * 180 / Math.PI;

        const br     = TO_RAD(DIRECTION); //br = bearing　方位角
        const φ1     = TO_RAD(CURRENT_LATITUDE);
        const λ1     = TO_RAD(CURRENT_LONGITUDE);   

        const φ2     = Math.asin(
                            Math.sin(φ1) * Math.cos(DISTANCE / EARTH_RADIUS) +
                            Math.cos(φ1) * Math.sin(DISTANCE / EARTH_RADIUS) * Math.cos(br)
                        );

        const λ2     = λ1 + Math.atan2(
                            Math.sin(br) * Math.sin(DISTANCE / EARTH_RADIUS) * Math.cos(φ1),
                            Math.cos(DISTANCE / EARTH_RADIUS) - Math.sin(φ1) * Math.sin(φ2)
                        );

        return {
            lat: TO_DEG(φ2),
            lng: TO_DEG(λ2)
        };
    }
    private calcEachSidePoint(CURRENT_LATITUDE : number, CURRENT_LONGITUDE : number, DIRECTION_RECORD : Record<string,number>, DISTANCE : number) : Record<string,any>{
        return {
                    LEFT_POINT  : this.WGS84_offsetPosition(CURRENT_LATITUDE,CURRENT_LONGITUDE,DIRECTION_RECORD.leftDir,DISTANCE),
                    RIGHT_POINT : this.WGS84_offsetPosition(CURRENT_LATITUDE,CURRENT_LONGITUDE,DIRECTION_RECORD.rightDir,DISTANCE)
                }
    }
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // ==============================================================================


    //======================Load CityData System===============================
    //=========================================================================
    loadCityDataSystem(CURRENT_LATITUDE : number, CURRENT_LONGITUDE : number, EACH_SIDE_COORD_RECORD : Record<string,any>) : void{
        // 市町村を読み込み、それに対応するファイルを読み込む。
        if(this.isOkToLoadCityCode()){
            this.loadWaypointGeoJSON_Data(CURRENT_LATITUDE,CURRENT_LONGITUDE,EACH_SIDE_COORD_RECORD)
        }
        this.loadWaypointPlaceName();
    }
    //~~~~~~~~~~~~~~~[load waypoint Geojson data]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    private async loadWaypointGeoJSON_Data(CURRENT_LATITUDE : number,CURRENT_LONGITUDE : number, EACH_SIDE_POINT_RECORD : Record<string,number>){
        const CURRENT_CITY_CODE     =  await this.getCityCode(CURRENT_LATITUDE,CURRENT_LONGITUDE);
        const LEFT_POINT_CITY_CODE  =  await this.getCityCode(EACH_SIDE_POINT_RECORD.LEFT_POINT.lat,EACH_SIDE_POINT_RECORD.LEFT_POINT.lng);
        const RIGHT_POINT_CITY_CODE =  await this.getCityCode(EACH_SIDE_POINT_RECORD.RIGHT_POINT.lat,EACH_SIDE_POINT_RECORD.RIGHT_POINT.lng);
        
        //現在地点の統計地理情報データ（GeoJSON)を読み込む。
        if(CURRENT_CITY_CODE === ""){
            // skip
        }else{
            this.CURRENT_GEO_DATA   = await this.loadGeoData(CURRENT_CITY_CODE);
        }

        //左方面地点の統計地理情報データ（GeoJSON)を読み込む。
        if(LEFT_POINT_CITY_CODE === CURRENT_CITY_CODE){
            this.LEFT_GEO_DATA      = this.CURRENT_GEO_DATA;
        }else if(LEFT_POINT_CITY_CODE === ""){
            // skip
        }else{
            this.LEFT_GEO_DATA      = await this.loadGeoData(LEFT_POINT_CITY_CODE);
        }

        //右方面地点の統計地理情報データ（GeoJSON)を読み込む。
        if(RIGHT_POINT_CITY_CODE === CURRENT_CITY_CODE){
            this.RIGHT_GEO_DATA     = this.CURRENT_GEO_DATA;
        }else if(RIGHT_POINT_CITY_CODE === ""){
            // skip
        }else{
            this.RIGHT_GEO_DATA     = await this.loadGeoData(RIGHT_POINT_CITY_CODE);
        }

        this.lastLaunchTime__loadWaypointGeoJSON_Data = Date.now();
    }
    async getCityCode(lat : number , lng : number):Promise<string>{
        const url   = `https://mreversegeocoder.gsi.go.jp/reverse-geocoder/LonLatToAddress?lat=${lat}&lon=${lng}`;
        const res   = await fetch(url);
        const data  = await res.json();
        
        this.debug_fetchCounter += 1;
        console.log(`fetch counter : ${this.debug_fetchCounter}`);

        // チェック：結果が存在するか確認
        if (data && data.results) {
            // results はオブジェクト（あるいは配列のような構造）なので、
            // 一般的には data.results.muniCode でアクセスできますが、
            // 念のため data.results をコンソールで確認してください。
            // console.log("取得データ:", data.results);

            return data.results.muniCd; // 統計地理情報システムの市区町村コードである数値（例：06203など）が返ります
        }
        
        return "";
    }
    async loadGeoData(CITY_CODE : string){
        const RESPONSE  = await fetch(`${CITY_CODE}.json`)
        const DATA      = await RESPONSE.json();
        // console.log(this.CURRENT_GEO_DATA);
        return DATA;
    }
    isOkToLoadCityCode(){//０．５秒ごとにロードしていたら、chromeがむり！！！ってエラー吐いたので1分毎にする。
        if(Date.now() - this.lastLaunchTime__loadWaypointGeoJSON_Data  > 1*10*1000){
            return true;
        }else{
            return false;
        }

    }
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    // ~~~~~~~~~~[load each waypoint of closest place name]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    private loadWaypointPlaceName(){
        const CURRENT_CITY_DATA =  this.calcClosestOoazaKoazaName(this.CURRENT_POINT.geometry.coordinates[0], this.CURRENT_POINT.geometry.coordinates[1]) as Record<string,string>;
        
        if(CURRENT_CITY_DATA !== undefined){
            console.log(CURRENT_CITY_DATA);
        
            this.currentKoazaOoaza  =  CURRENT_CITY_DATA.OOAZA_AND_KOAZA;
            this.current_cityName   =  CURRENT_CITY_DATA.CITY_NAME;
            this.current_prefName   =  CURRENT_CITY_DATA.PREF_NAME;

            const LEFT_CITY_DATA    =  this.calcClosestOoazaKoazaName(this.LEFT_POINT.geometry.coordinates[0],    this.LEFT_POINT.geometry.coordinates[1]) as Record<string,string>;
            this.leftKoazaOoaza     =  LEFT_CITY_DATA.OOAZA_AND_KOAZA;
            this.left_cityName      =  LEFT_CITY_DATA.CITY_NAME;
            this.left_prefName      =  LEFT_CITY_DATA.PREF_NAME;

            const RIGHT_CITY_DATA   =  this.calcClosestOoazaKoazaName(this.RIGHT_POINT.geometry.coordinates[0],   this.RIGHT_POINT.geometry.coordinates[1]) as Record<string,string>;
            this.rightKoazaOoaza    =  RIGHT_CITY_DATA.OOAZA_AND_KOAZA;
            this.right_cityName     =  RIGHT_CITY_DATA.CITY_NAME;
            this.right_prefName     =  RIGHT_CITY_DATA.PREF_NAME;
        }else{
            console.log(`oh undefined////`)
        }
    }
    private calcClosestOoazaKoazaName(USER_LNG : number, USER_LAT : number) : Record<string,string> | void{
        if (!this.CURRENT_GEO_DATA) return;

        let minDistance = Infinity;
        let closestOoazaAndKoaza = "判定中...";

        var cityName = "";
        var prefName = "";

        turf.featureEach(this.CURRENT_GEO_DATA, (feature: any) => {
            const props = feature.properties;
            
            // X_CODE と Y_CODE が存在するかチェック
            if (props.X_CODE && props.Y_CODE) {
                // 現在地と、各町の代表地点(X_CODE, Y_CODE)の距離を計算
                // ※簡易的な計算式ですが、小字レベルなら十分です
                const dx         = USER_LNG - props.X_CODE;
                const dy         = USER_LAT - props.Y_CODE;
                const distanceSq = dx * dx + dy * dy; // 距離の2乗

                // 一番近い町を更新していく
                if (distanceSq < minDistance) {
                    minDistance  = distanceSq;
                    closestOoazaAndKoaza = props.S_NAME;
                }

                cityName = props.CITY_NAME;
                prefName = props.PREF_NAME;
            }
        });

        return {
            OOAZA_AND_KOAZA  : closestOoazaAndKoaza,
            CITY_NAME        : cityName,
            PREF_NAME        : prefName
        }
    } 
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    //=========================================================================


    //=========== Announce System ================================================================  
    //===============================================================================
    Announce(){
        // 1. どこかに変化があるかチェック（前回と全く同じなら何もしない）
        const hasCurrentChanged = !this.isOoazaAndKoazaSame(this.currentKoazaOoaza, "CURRENT");
        const hasLeftChanged    = !this.isOoazaAndKoazaSame(this.leftKoazaOoaza, "LEFT");
        const hasRightChanged   = !this.isOoazaAndKoazaSame(this.rightKoazaOoaza, "RIGHT");

        if (!hasCurrentChanged && !hasLeftChanged && !hasRightChanged) {
            return; // どこも変わってなければ終了
        }

        window.speechSynthesis.cancel();

        const CONTENT       = this.writeAnnounceContent(hasCurrentChanged,hasLeftChanged,hasRightChanged);

        const UTTR          = new SpeechSynthesisUtterance(CONTENT);
        UTTR.lang           = "ja-JP";

        const SPEED_SLIDER  = document.getElementById("speed-val") as HTMLElement;
        UTTR.rate           = parseFloat(SPEED_SLIDER.textContent);
        UTTR.pitch          = 1.0;
        // console.log("in anouunce true")
        window.speechSynthesis.speak(UTTR);          
    }

    private isOoazaAndKoazaSame(OOAZA_KOAZA : string, WAYPOINT_KEY : string) : boolean{
        return OOAZA_KOAZA === this.previousKoaza[WAYPOINT_KEY] ? true : false;
    }
    private isCityNameSame(CITY_NAME : string, WAYPOINT_KEY : string) : boolean{
        return CITY_NAME === this.previousCityName[WAYPOINT_KEY] ? true : false;
    }
    private isPrefNameSame(PREF_NAME : string, WAYPOINT_KEY : string) : boolean{
        return PREF_NAME === this.previousPrefName[WAYPOINT_KEY] ? true : false;
    }
    //WAYPOINT_KEY : CURRENT, LEFT, RIGHT

    private writeAnnounceContent(hasCurrentChanged: boolean, hasLeftChanged: boolean, hasRightChanged: boolean) {
        const REST = "、、、、、、";

        // LOC_REC の各プロパティが LocationData 型であることを明示
        const LOC_REC: Record<"CURRENT" | "LEFT" | "RIGHT", LocationData> = {
                CURRENT: { 
                    label: "げんざい", 
                    name: this.currentKoazaOoaza, 
                    pref: this.current_prefName, 
                    city: this.current_cityName, 
                    type: "CURRENT" 
                },
                LEFT: { 
                    label: "ひだり", 
                    name: this.leftKoazaOoaza,    
                    pref: this.left_prefName,    
                    city: this.left_cityName,    
                    type: "LEFT" 
                },
                RIGHT: { 
                    label: "みぎ", 
                    name: this.rightKoazaOoaza,   
                    pref: this.right_prefName,   
                    city: this.right_cityName,   
                    type: "RIGHT" 
                }
        };

        // 1. 変化があった方位のキーを配列に入れる (例: ["CURRENT", "LEFT"])
        const changedKeys: ("CURRENT" | "LEFT" | "RIGHT")[] = [];
        if (hasCurrentChanged) changedKeys.push("CURRENT");
        if (hasLeftChanged)    changedKeys.push("LEFT");
        if (hasRightChanged)   changedKeys.push("RIGHT");


        // 2. 方位のグループ化（読み上げの「主語」を決定）
        let groups :AnnounceGroup[] = [];

        // 2. 変化した方位同士の地名を比較してグループ化
        if (changedKeys.length === 3 && 
            LOC_REC.CURRENT.name === LOC_REC.LEFT.name && 
            LOC_REC.LEFT.name === LOC_REC.RIGHT.name) {
            
            // ケース1: 全方位が同時に同じ地名に変わった
            groups.push({ ...LOC_REC.CURRENT, directionTitle: "ぜんほうい", repeat: true });

        }else if(LOC_REC.CURRENT.name === LOC_REC.LEFT.name  && LOC_REC.CURRENT.name === LOC_REC.RIGHT.name){
            // いずれかに変化があり、結果三方一致した場合
            groups.push({ ...LOC_REC.CURRENT, directionTitle: "ぜんほうい", repeat: true });
        }else {
            // ケース2: 変化があった方位の中で、同じ地名のものをまとめる
            // 判定用の作業配列 
            // ※注釈 Set<>()は重複のない集合objectです。hasで要素の有無を調べ、addで新たな要素を入れられます。
            //　 Array（配列）と異なり、同じ要素をaddしても重複しません。また、hasは高速検索機能があります。
            const handled = new Set<string>();

            changedKeys.forEach(key => {
                if (handled.has(key)) return;


                // ※fileterについて
                //   このメソッドはfilter(条件)として使います。
                // 　これは、条件に合った要素のみを抽出して、新たな配列を作ります。
                const sameNameKeys = changedKeys.filter(otherKey => 
                    // 他の変化した方位の中に、同じ地名のものがあるか探し、抽出。
                    LOC_REC[key].name === LOC_REC[otherKey].name
                );

                // ラベルの組み立て (例: "げんざいとひだりは")
                let title = "";
                if (sameNameKeys.length === 3) {
                    title = "ぜんほうい";
                } else if (sameNameKeys.includes("CURRENT") && sameNameKeys.includes("LEFT")) {
                    title = "げんざいとひだりは";
                } else if (sameNameKeys.includes("CURRENT") && sameNameKeys.includes("RIGHT")) {
                    title = "げんざいとみぎは";
                } else if (sameNameKeys.includes("LEFT") && sameNameKeys.includes("RIGHT")) {
                    title = "さゆう";
                } else {
                    title = LOC_REC[key].label; // 単独
                }

                groups.push({ ...LOC_REC[key], directionTitle: title });

                // 処理済みリストに追加
                sameNameKeys.forEach(k => handled.add(k));
            });
        }
            // =====================================================================================
            // TIPS: 今回geminiがスプレッド構文を紹介してくれました。
            // スプレッド構文 { ．．．PARENT.KEY}
            // 構文なしで書くと以下のようになります。　　　　　　　　スプレッド構文だとこうなります。
                // groups.push({                               groups.push({
                //     label: LOC_REC.CURRENT.label,                  ...LOC_REC.CURRENT,
                //     name:  LOC_REC.CURRENT.name,　　　　　　　　　　　　　　
                //     pref:  LOC_REC.CURRENT.pref,　　　　　　　　　   //新しく追加
                //     city:  LOC_REC.CURRENT.city,　　　　　　　　　   directionTitle: ["ぜんほうい"],
                //     type:  LOC_REC.CURRENT.type,                    repeat: true
                //                                                 });
                //     // 新しく追加
                //     directionTitle: ["ぜんほうい"], 
                //     repeat: true 
                // });
            // レコードの同一keyをすべて展開できるのが　スプレッド構文です。可読性があがりますね。
            // =========================================================================================

        // 3. 各グループを文章化して連結
        return groups.map(g => {
            // 都道府県・市町村を含めるか判定
            let prefix = "";
            const isPrefDiff = !this.isPrefNameSame(g.pref, g.type);
            const isCityDiff = !this.isCityNameSame(g.city, g.type);

            if (isPrefDiff) {
                prefix = `${g.pref}${g.city}${REST}`;
            } else if (isCityDiff) {
                prefix = `${g.city}${REST}`;
            }

            const parts = this.produceSeparationOfOoazaKoaza(g.name);
            var main : string = "";
            if(g.directionTitle === "ぜんほうい"){
                main = `${g.directionTitle}、${prefix}${g.name}。${parts[0]}${REST}${parts[1]}にはいりました。`;
            }else{
                main = `${g.directionTitle}、${parts[1]}。`
            }
         
            return g.repeat ? `${main}繰り返します。${REST}${main}` : main;
        }).join(REST);
    }
    private produceSeparationOfOoazaKoaza(rawName: string): string[] {
        const REST = "、、、、、、";
        // "大字"を削り、"字"で分割
        const cleanName = rawName.replace("大字", "");
        const [ooaza, koaza] = cleanName.split("字");

        if (koaza) {
            // 読み上げ用の詳細形式と、短縮形式を返す
            const detail = rawName.includes("大字") 
                ? `おおあざ${REST}${ooaza}${REST}あざ${REST}${koaza}` 
                : `${ooaza}${REST}あざ${REST}${koaza}`;
            return [detail, `${ooaza}の${REST}${koaza}`];
        }
        
        return [`${ooaza}${REST}`, ooaza];
    }
    //===============================================================================


    
    private updatePreviousePlaceNames(){
        // 履歴の更新
        const sides = ["CURRENT", "LEFT", "RIGHT"] as const;
        const data = {
            CURRENT: { koaza: this.currentKoazaOoaza, city: this.current_cityName, pref: this.current_prefName },
            LEFT:    { koaza: this.leftKoazaOoaza,    city: this.left_cityName,    pref: this.left_prefName },
            RIGHT:   { koaza: this.rightKoazaOoaza,   city: this.right_cityName,   pref: this.right_prefName }
        };

        sides.forEach(side => {
            this.previousKoaza[side]    = data[side].koaza;
            this.previousCityName[side] = data[side].city;
            this.previousPrefName[side] = data[side].pref;
        });

    }

    private playInNewCitySound(){


        if(this.isPrefNameSame(this.current_prefName,"CURRENT") == false){
            switch(this.current_prefName){
                case "山形県":
                     new Audio("YamagataSong_Mogamigawa.mp3").play();
                     break;

                default:
                    new Audio("inNewPref.mp3").play();
            }
            
            
        }else if (this.isCityNameSame(this.current_cityName,"CURRENT")== false){
            new Audio("inNewCity.mp3").play();
        }
    }


    DisplayInfo() {
        const CURRENT_KOAZA_DISPLAY     = document.getElementById("current-koaza")          as HTMLDivElement;
        const LONGITUDE_DISPLAY         = document.getElementById("lng-val")                as HTMLDivElement;
        const LATITUDE_DISPLAY          = document.getElementById("lat-val")                as HTMLDivElement;
        const LEFT_KOAZA_DISPLAY        = document.getElementById("left-koaza")             as HTMLDivElement;
        const RIGHT_KOAZA_DISPLAY       = document.getElementById("right-koaza")            as HTMLDivElement;
        const CURRENT_PREF_CITY_DISPLAY = document.getElementById("currentPrefCityName")    as HTMLParagraphElement;

        // ヘルパー関数：変化がある部分だけを文字列にする
        const formatDisplayString = (pref: string, city: string, koaza: string, key: string) => {
            const isPrefSame = this.isPrefNameSame(pref, key);
            const isCitySame = this.isCityNameSame(city, key);

            if (!isPrefSame) {
                // 県が変わった場合：全部表示
                return `${pref} ${city}<br>${koaza}`;
            } else if (!isCitySame) {
                // 県は同じだが、市が変わった場合：市から表示
                return `${city}<br>${koaza}`;
            } else {
                // 県も市も同じ場合：小字（大字）のみ表示
                return `${koaza}`;
            }
        };

        // 各要素の書き換え
        CURRENT_KOAZA_DISPLAY.innerHTML = formatDisplayString(
            this.current_prefName, this.current_cityName, this.currentKoazaOoaza, "CURRENT"
        );

        LEFT_KOAZA_DISPLAY.innerHTML = formatDisplayString(
            this.left_prefName, this.left_cityName, this.leftKoazaOoaza, "LEFT"
        );

        RIGHT_KOAZA_DISPLAY.innerHTML = formatDisplayString(
            this.right_prefName, this.right_cityName, this.rightKoazaOoaza, "RIGHT"
        );

        CURRENT_PREF_CITY_DISPLAY.innerHTML = `${this.current_prefName} ${this.current_cityName}`;

        // 座標の表示
        LONGITUDE_DISPLAY.innerHTML = this.CURRENT_POINT.geometry.coordinates[0].toString();
        LATITUDE_DISPLAY.innerHTML = this.CURRENT_POINT.geometry.coordinates[1].toString();
    }

    addHistoryLog(){
        const hasCurrentChanged = !this.isOoazaAndKoazaSame(this.currentKoazaOoaza, "CURRENT");
        if(hasCurrentChanged){
            const LOG       = document.getElementById('history-log') as HTMLElement;
            const li        = document.createElement('li');
            const SPACE     = "&nbsp;".repeat(17);
            li.innerHTML    = `${new Date().toLocaleTimeString()} - [現在地点]${this.current_prefName} ${this.current_cityName} ${this.currentKoazaOoaza}<br>${SPACE}[左方面地点]${this.left_prefName} ${this.left_cityName} ${this.leftKoazaOoaza}<br>${SPACE}[右方面地点]${this.right_prefName} ${this.right_cityName} ${this.rightKoazaOoaza}`;
            LOG?.prepend(li);

            this.sendHistoryLogToFirebase();
        }


        
    }
    sendHistoryLogToFirebase(){
        const LOG = document.getElementById('history-log') as HTMLElement;
        this.FIREBASE_FUNCTION.uploadData(`yamato/history/${this.APP_START_TIME}`,LOG.innerHTML);
        
    }
    //===========================================================================
    //====================================================================================
    






    //other function in Init
    attachEvent(){
        const INTERVAL_INPUT    = document.getElementById("interval-input")     as HTMLInputElement;
        INTERVAL_INPUT.addEventListener("input",()=>{
            this.intervalSystem();
        })

        const MODE_INPUT                = document.getElementById("mode-input")      as HTMLInputElement;
        MODE_INPUT.addEventListener("input",()=>{
            this.loadUserParameterAndInput();
        })
    }

    intervalSystem(){
        if(this.intervalID){
            this.resetInterval();
            this.setNewInterval();
        }else{
            this.setNewInterval();
        }
    }
    private setNewInterval(){
        const INTERVAL_INPUT    = document.getElementById("interval-input")     as HTMLInputElement;
        const INTERVAL_SECOND   = parseInt(INTERVAL_INPUT.value)*1000; 
        this.intervalID = setInterval(() => {
                                                    this.naviMainSystem();
                                            }, INTERVAL_SECOND);
    }
    private resetInterval(){
        clearInterval(this.intervalID);
        this.intervalID = null;
    }

    private async loadUserParameterAndInput() {
        try {
            // 1. データのダウンロードを確実に待機
            const MODE_INPUT                = document.getElementById("mode-input")      as HTMLInputElement;
            const MODE                      = MODE_INPUT.value;
            const [accuracyData, distanceData,speedData,intervalData] = await Promise.all([
                this.FIREBASE_FUNCTION.downloadData(`yamato/${MODE}/accuracyThreshold`  ),
                this.FIREBASE_FUNCTION.downloadData(`yamato/${MODE}/rightLeftDistance`  ),
                this.FIREBASE_FUNCTION.downloadData(`yamato/${MODE}/speachSpeed`        ),
                this.FIREBASE_FUNCTION.downloadData(`yamato/${MODE}/interval`           )
            ]);

            // 2. 要素を HTMLInputElement として取得
            const THRESHOLD_EL      = document.getElementById("threshold-input")    as HTMLInputElement;
            const DISTANCE_EL       = document.getElementById("distance-input")     as HTMLInputElement;
            const SPEED_DISPLAY     = document.getElementById("speed-input")        as HTMLInputElement;
            const SPEED_VAL         = document.getElementById("speed-val")          as HTMLElement;
            const INTERVAL_INPUT    = document.getElementById("interval-input")     as HTMLInputElement;

            // 3. .value を使って値をセット（データがない場合はデフォルト値を表示）
            if (THRESHOLD_EL) {
                THRESHOLD_EL.value = accuracyData !== undefined ? accuracyData : "100";
                // 視覚的エフェクトをトリガー
                THRESHOLD_EL.classList.add('setting-updated');
            }

            if (DISTANCE_EL) {
                DISTANCE_EL.value = distanceData !== undefined ? distanceData : "100";
                // 視覚的エフェクトをトリガー
                DISTANCE_EL.classList.add('setting-updated');
            }

            if(SPEED_DISPLAY){
                SPEED_DISPLAY.value   = speedData;
                SPEED_VAL.textContent = speedData !== undefined ? speedData : "1.0";

                SPEED_DISPLAY.classList.add("setting-updated");
                
            }

            if (INTERVAL_INPUT) {
                INTERVAL_INPUT.value = intervalData !== undefined ? intervalData : "1";
                // 視覚的エフェクトをトリガー
                INTERVAL_INPUT.classList.add('setting-updated');
            }


            console.log("Firebaseからのロード完了:", { accuracyData, distanceData });

        } catch (error) {
            console.error("データの読み込み中にエラーが発生しました:", error);
        }
    }

    private setupSettingEffect() {
        const inputs = ['threshold-input', 'distance-input',"interval-input"];
        
        inputs.forEach(id => {
            const el = document.getElementById(id) as HTMLInputElement;
            if (!el) return;

            el.addEventListener('change', () => {
                // クラスを一度消して再付与することで、連続変更でもアニメーションを走らせる
                el.classList.remove('setting-updated');
                void el.offsetWidth; // リフローを強制（アニメーションのリセットに必要）
                el.classList.add('setting-updated');
                
                console.log(`${id} が変更されました: ${el.value}`);
            });
        });
    }




}

class History{
    FIREBASE_FUNCTION : FirebaseFunctions;

    constructor(FIREBASE_FUNCTION :FirebaseFunctions){  
        this.FIREBASE_FUNCTION = FIREBASE_FUNCTION;
        this.attachEvents();

        this.init();
    }

    attachEvents(){
        const SHOW_HISTORY_BTN = document.getElementById("historyBtn") as HTMLElement;
            SHOW_HISTORY_BTN.addEventListener("click",()=>{
                this.openHistoryLogModal();
            })

        const CLOSE_HISTORY_BTN = document.getElementById("closeBtn") as HTMLElement;
        CLOSE_HISTORY_BTN.addEventListener("click",()=>{
            this.closeHistoryModal();
        })

        const SAVE_PARAETER_BTN = document.getElementById("saveSettingsBtn") as HTMLElement;
        SAVE_PARAETER_BTN.addEventListener("click",()=>{
            this.sendParameterToFirebse();
            SAVE_PARAETER_BTN.classList.remove("save-success");
            void(SAVE_PARAETER_BTN as HTMLElement).offsetWidth;
            SAVE_PARAETER_BTN.classList.add("save-success");
        })

        const SPEED_SLIDER  = document.getElementById("speed-input")    as HTMLElement;
        const SPEED_DISPLAY = document.getElementById("speed-val")      as HTMLElement;
        SPEED_SLIDER.addEventListener("input",(e : any) => {
            console.log( parseFloat(e.target.value).toFixed(1))
            SPEED_DISPLAY.textContent = parseFloat(e.target.value).toFixed(1);
        })

 
    }
    sendParameterToFirebse(){
       
        const ACCURACY_THRESHOLD_INPUT  = document.getElementById("threshold-input") as HTMLInputElement;
        const RL_DISTANCE_INPUT         = document.getElementById("distance-input")  as HTMLInputElement;
        const SPEED_DISPLAY             = document.getElementById("speed-val")       as HTMLElement;
        const INTERVAL_INPUT            = document.getElementById("interval-input")  as HTMLInputElement;

        const MODE_INPUT                = document.getElementById("mode-input")      as HTMLInputElement;
        const MODE                      = MODE_INPUT.value;

        this.FIREBASE_FUNCTION.uploadData(`yamato/${MODE}/accuracyThreshold`,ACCURACY_THRESHOLD_INPUT.value );
        this.FIREBASE_FUNCTION.uploadData(`yamato/${MODE}/rightLeftDistance`,RL_DISTANCE_INPUT.value        );
        this.FIREBASE_FUNCTION.uploadData(`yamato/${MODE}/speachSpeed`      ,SPEED_DISPLAY.textContent      );
        this.FIREBASE_FUNCTION.uploadData(`yamato/${MODE}/interval`         ,INTERVAL_INPUT.value           )
    }


    async init(){
        const ALL_DATA_RECORD =  await this.loadAllHistory();
        this.displayHistorySections(ALL_DATA_RECORD);
    

    }
    async loadAllHistory(){
        const DATA = await this.FIREBASE_FUNCTION.downloadData("yamato/history");
        const TIMESTAMPS =Object.keys(DATA);
        const NEW_RECORD  : Record<string,string>= {};

            // タイムスタンプ（キー）を数値としてソート（降順：新しい順）
        const SORTED_KEYS = Object.keys(DATA).sort((a, b) => {
                return parseInt(b) - parseInt(a);
            });

            SORTED_KEYS.forEach(ts => {
                // 日時をキー名にする（例: "2026/1/6 12:21:32"）
                const dateKey = new Date(parseInt(ts)).toLocaleString();

                try {
                    // 文字列化されたJSONを配列に戻す
                    const dataArray = JSON.parse(DATA[ts]);
                    // 配列の1番目（HTMLContent）を取得
                    const htmlContent = dataArray[1];

                    // 新しいRecordに格納
                    NEW_RECORD[dateKey] = htmlContent;
                } catch (e) {
                    console.error(`解析エラー: ${ts}`, e);
                }
            });

            return NEW_RECORD;
    }
    displayHistorySections(ALL_DATA_RECORD : Record<string,string>){
        Object.entries(ALL_DATA_RECORD).forEach(([dateKey,htmlContent])=>{
            const LIST = this.createList(dateKey);
            this.attachOnClickEvent(LIST,htmlContent);

            const INDEX_Ul = document.getElementById('history-index') as HTMLElement;
            INDEX_Ul.appendChild(LIST);

        })
    }

    createList(dateKey : string){
        const LIST = document.createElement(`li`);

        LIST.innerHTML = `
        <div class="history-header">
            <span class="calendar-icon">📅</span>
            <span class="date-text">${dateKey}</span>
        </div>
        `;

        LIST.className = "history-summary-item";

        return LIST;
    }

    attachOnClickEvent(LIST : HTMLElement, HTML_CONTENT : string){
        LIST.onclick = () =>{
            const PREVIEW_Ul = document.getElementById('history-log-preview') as HTMLElement;
            PREVIEW_Ul.innerHTML = HTML_CONTENT;

            const INDEX_Ul = document.getElementById('history-index') as HTMLElement;
            Array.from(INDEX_Ul.children).forEach(el => el.classList.remove("is-active"));
            LIST.classList.add("is-active");

            PREVIEW_Ul.scrollIntoView({behavior : "smooth", block : "nearest"});
        }
    }




    openHistoryLogModal(){
        const MODAL = document.getElementById("history-overlay") as HTMLElement;
        MODAL.style.display = "block";
    }

    closeHistoryModal(){
        const MODAL = document.getElementById("history-overlay") as HTMLElement;
        MODAL.style.display = "none";
    }


}

class Camera{
    stream! : any;

    constructor(){
        this.setupCameraControls();
        this.setUpCameraSize();
    }
    private setUpCameraSize(){
       
        
        const cameraContainer = document.getElementById("camera-container") as HTMLDivElement;
       
        try {
        // 1. .card 要素（location-card）の現在のサイズを取得
        const locationCard = document.querySelector(".location-card") as HTMLElement;
        if (locationCard) {
            const rect = locationCard.getBoundingClientRect();
            
            // 2. 指定の比率（高さ40%、幅20%）を計算
            // ※「上」に配置する場合、幅100%の方が収まりが良いですが、
            // ご要望通りpxで代入します。
            const dynamicWidth = rect.width * 0.8;
            const dynamicHeight = rect.height * 0.6;

            // 3. カメラコンテナにpx単位で適用
            cameraContainer.style.width = `${dynamicWidth}px`;
            cameraContainer.style.height = `${dynamicHeight}px`;
            
            // 中央寄せしたい場合は以下を追加
            cameraContainer.style.margin = "0 auto 15px auto"; 
        }

        // // カメラ起動処理
        // this.stream = await navigator.mediaDevices.getUserMedia({
        //     video: { facingMode: "environment" }
        // });
        // videoElement.srcObject = this.stream;
        // videoElement.play();
        // containerElement.classList.remove("hidden");

    } catch (err) {
        console.error("カメラの起動に失敗しました:", err);
        alert("カメラを起動できませんでした。");
    }
    }

    private setupCameraControls() {
        const toggleCameraBtn = document.getElementById("toggle-camera-btn");
        const closeCameraBtn = document.getElementById("close-camera-btn");
        const cameraContainer = document.getElementById("camera-container");
        const cameraFeed = document.getElementById("camera-feed") as HTMLVideoElement;

        if (toggleCameraBtn && closeCameraBtn && cameraContainer && cameraFeed) {
            toggleCameraBtn.addEventListener("click", () => {
                if (cameraContainer.classList.contains("hidden")) {
                    this.startCamera(cameraFeed, cameraContainer);
                } else {
                    this.stopCamera(cameraContainer);
                }
            });

            closeCameraBtn.addEventListener("click", () => {
                this.stopCamera(cameraContainer);
            });
        }
    }

    private async startCamera(videoElement: HTMLVideoElement, containerElement: HTMLElement) {
        try {
            this.stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: "environment" // 背面カメラを優先。'user'で前面カメラ
                }
            });
            videoElement.srcObject = this.stream;
            videoElement.play();
            containerElement.classList.remove("hidden");
        } catch (err) {
            console.error("カメラの起動に失敗しました:", err);
            alert("カメラの利用が許可されていないか、利用できません。");
        }
    }

    private stopCamera(containerElement: HTMLElement) {
        if (this.stream) {
            this.stream.getTracks().forEach(track => track.stop());
            this.stream = null;
        }
        const videoElement = containerElement.querySelector("video");
        if (videoElement) {
            videoElement.srcObject = null;
        }
        containerElement.classList.add("hidden");
    }
}


const APP_START_BTN = document.getElementById("startBtn") as HTMLElement;
APP_START_BTN.addEventListener("click",()=>{
    const APP = new App(FIREBASE_FUNCTION);
})
const HISTORY = new History(FIREBASE_FUNCTION);
const CAMERA  = new Camera();


