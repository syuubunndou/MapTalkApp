var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _FirebaseFunctions_instances, _FirebaseFunctions___loginWithGoogle, _FirebaseFunctions___logoutFromGoogle, _FirebaseFunctions___isLogined, _FirebaseFunctions___applyByAuthStateChange, _FirebaseFunctions___applyBySignInWithRedirect, _FirebaseFunctions___translateSignErrors, _FirebaseFunctions___fetchGoogleAccountData, _FirebaseFunctions___uploadAndResetInfo, _FirebaseFunctions___alertMessage, _FirebaseFunctions___initTipFlg, _FirebaseFunctions___tellTips, _FirebaseFunctions___showCaution, _UrlFunction_instances, _UrlFunction___composeURLbyPageTitle, _UrlFunction___returnHomePageURL, _HtmlFunction_instances, _HtmlFunction___resetPlaceHolder, _HtmlFunction___getRawText, _HtmlFunction___setValueToContentElement, _HtmlFunction___validateLengthWithin, _HtmlFunction___setCursorToEnd, _HtmlFunction___onlyNumbers, _HtmlFunction___onlySelectedNumberRange, _HtmlFunction___withinMonthlyDate, _HtmlFunction___validateMonthlyDate, _HtmlFunction___zeroPadding, _HtmlFunction___renderWeekday, _HtmlFunction___isLaunchEvent, _PreLoader_instances, _PreLoader_startAutoCloseSelfTimerMonitor, _PreLoader_isReadyToCloseSelfTimerPreloader, _PreLoader_isHaveFirebaseApp, _PreLoader_sendStartSignalToFirebase, _PreLoader_startAutoCloseBroadcastMonitor, _PreLoader_isReadyToCloseBroadcastPreloader;
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js";
import { getDatabase, ref, push, get, set, remove } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-database.js";
import { getAuth, signInWithPopup, getRedirectResult, signInWithRedirect, GoogleAuthProvider, onAuthStateChanged, signOut, } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js";
import { getFirestore, doc, getDoc } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-firestore.js";
import * as turf from 'https://cdn.skypack.dev/@turf/turf';
const REDIRECT_OPTIONS = [true, false];
const RENDER_AUTH_METHOD_OPTIONS = ["signInWithPopup", "onAuthStateChanged", "signInWithRedirect"];
class FirebaseFunctions {
    constructor(FIREBASE_CONFIG, IS_LOGIN_REQUIRED) {
        _FirebaseFunctions_instances.add(this);
        this.isShowTip = {};
        const APP = initializeApp(FIREBASE_CONFIG);
        this.FIRESTORE_DB = getFirestore(APP);
        this.DB = getDatabase(APP);
        this.PROVIDER = new GoogleAuthProvider();
        this.AUTH = getAuth();
        this.UID = "";
        this.ACCOUNT_DATA = {};
        this.ACCESS_TOKEN = "";
        this.IV = crypto.getRandomValues(new Uint8Array(12));
        this.SALT = crypto.getRandomValues(new Uint8Array(16));
        this.IS_LOGIN_REQUIRED = IS_LOGIN_REQUIRED;
        this.UtilsFunc = new UtilsFunctions();
        this.preloader = new PreLoader();
        __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___initTipFlg).call(this);
    }
    downloadKeyFromFireStore(COLLECTION_NAME, DOCUMENT_ID, FIELD_NAME) {
        return __awaiter(this, void 0, void 0, function* () {
            const docRef = doc(this.FIRESTORE_DB, COLLECTION_NAME, DOCUMENT_ID);
            const docSnap = yield getDoc(docRef);
            try {
                if (docSnap.exists()) {
                    return docSnap.data()[FIELD_NAME];
                }
                else {
                    console.error("APIキーがFirestoreに存在しません");
                    return null;
                }
            }
            catch (error) {
                console.error("APIキーの取得に失敗しました:", error);
                return null;
            }
        });
    }
    deleteData(rawPath) {
        const USER_PATH = `${this.UID}/${rawPath}`;
        const DB_REF_DATA = ref(this.DB, USER_PATH);
        remove(DB_REF_DATA);
    }
    uploadExpiringCookie(data, EXPIRE_AFTER_X_TIME = 3000) {
        var expire = new Date();
        expire.setTime(expire.getTime() + EXPIRE_AFTER_X_TIME);
        const DB_REF_DATA = ref(this.DB, `${this.UID}/cookie`);
        if (typeof (data) == "object" && Array.isArray(data) == false) {
        }
        else {
            __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___showCaution).call(this, "uploadExpiringCookie", data);
        }
        const LIST_DATA = [expire, data];
        const JSON_DATA = JSON.stringify(LIST_DATA);
        set(DB_REF_DATA, JSON_DATA);
    }
    uploadData(rawPath, data) {
        const USER_PATH = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
        const DB_REF_DATA = ref(this.DB, USER_PATH);
        if (typeof (data) == "string") {
            data = ["json", data];
        }
        const JSON_DATA = JSON.stringify(data);
        set(DB_REF_DATA, JSON_DATA);
    }
    prepareUniqueID() {
        const TEMP_REF = ref(this.DB);
        const ID = push(TEMP_REF).key;
        return ID;
    }
    decryptData(ENCRYPTED_HEX, SALT_HEX, IV_HEX, PASSWORD) {
        return __awaiter(this, void 0, void 0, function* () {
            if (PASSWORD) {
            }
            else {
                PASSWORD = "";
            }
            if (this.ACCOUNT_DATA && this.ACCOUNT_DATA.uid) {
                const ENCODER = new TextEncoder();
                const DECODER = new TextDecoder();
                const ENCRYPTED_BYTES = new Uint8Array(ENCRYPTED_HEX.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const SALT_BYTES = new Uint8Array(SALT_HEX.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const IV_BYTES = new Uint8Array(IV_HEX.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                const UID = this.ACCOUNT_DATA.uid;
                const FIREBASE_CREATE_AT = this.ACCOUNT_DATA.metadata.createdAt;
                const COMBINED_RAW_KEY = `${UID}${FIREBASE_CREATE_AT}${PASSWORD}`;
                const COMBINED_BUFFER = new Uint8Array([...ENCODER.encode(COMBINED_RAW_KEY), ...SALT_BYTES]);
                const HASH_BUFFER = yield crypto.subtle.digest("SHA-256", ENCODER.encode(COMBINED_BUFFER));
                const KEY = yield crypto.subtle.importKey("raw", HASH_BUFFER, { name: "AES-GCM" }, false, ["decrypt"]);
                try {
                    const DECRYPTED_BUFFER = yield crypto.subtle.decrypt({ name: "AES-GCM", iv: IV_BYTES }, KEY, ENCRYPTED_BYTES);
                    const DECRYPTED_STRING = DECODER.decode(DECRYPTED_BUFFER);
                    return JSON.parse(DECRYPTED_STRING);
                }
                catch (error) {
                    console.error("復号エラー:", error);
                    return null;
                }
            }
            else {
                console.log(`ログアウト時にFirebaseFunctionsのprepareGoogleUserIDが実行されました。そのため、実行を拒否しました。再試行します。`);
                this.preloader.charWaterflow("SleepTimerMode");
                yield this.UtilsFunc.sleep(1000, this.preloader, { preloder: "charWaterflow" });
                this.preloader.closePreLoader("SleepTimerMode");
                this.decryptData(ENCRYPTED_HEX, SALT_HEX, IV_HEX);
            }
        });
    }
    encryptData(DATA, PASSWORD) {
        return __awaiter(this, void 0, void 0, function* () {
            if (PASSWORD) {
            }
            else {
                PASSWORD = "";
            }
            if (this.ACCOUNT_DATA && this.ACCOUNT_DATA.uid) {
                const UID = this.ACCOUNT_DATA.uid;
                const FIREBASE_CREATE_AT = this.ACCOUNT_DATA.metadata.createdAt;
                const ENCODER = new TextEncoder();
                const COMBINED_RAW_KEY = `${UID}${FIREBASE_CREATE_AT}${PASSWORD}`;
                const COMBINED_BUFFER = new Uint8Array([...ENCODER.encode(COMBINED_RAW_KEY), ...this.SALT]);
                const HASH_BUFFER = yield crypto.subtle.digest("SHA-256", ENCODER.encode(COMBINED_BUFFER));
                const KEY = yield crypto.subtle.importKey("raw", HASH_BUFFER, { name: "AES-GCM" }, false, ["encrypt"]);
                const DATA_STRING = JSON.stringify(DATA);
                const ENCRYPTED_BUFFER = yield crypto.subtle.encrypt({ name: "AES-GCM", iv: this.IV }, KEY, ENCODER.encode(DATA_STRING));
                const ENCRYPTED_HEX = Array.from(new Uint8Array(ENCRYPTED_BUFFER)).map(b => b.toString(16).padStart(2, "0")).join("");
                const SALT_HEX = Array.from(this.SALT).map(b => b.toString(16).padStart(2, "0")).join("");
                const IV_HEX = Array.from(this.IV).map(b => b.toString(16).padStart(2, "0")).join("");
                return { data: ENCRYPTED_HEX, salt: SALT_HEX, iv: IV_HEX };
            }
            else {
                console.log(`ログアウト時にFirebaseFunctionsのprepareGoogleUserIDが実行されました。そのため、実行を拒否しました。再試行します。`);
                yield this.UtilsFunc.sleep(1000, this.preloader, { preloder: "charWaterflow" });
                this.encryptData(DATA);
            }
        });
    }
    isEncryptedString(DATA) {
        const MIN_ENCRYPTED_LENGTH = 36;
        const IS_OVER_LENGTH36 = DATA.length >= MIN_ENCRYPTED_LENGTH ? true : false;
        const IS_INCLUDE_NON_ALPHANUMERIC = /[^a-zA-Z0-9]/.test(DATA);
        const IS_ONLY_ALPHABET = /^[a-zA-Z]+$/.test(DATA);
        const IS_ONLY_NUMBER = /^[0-9]+$/.test(DATA);
        const result = IS_OVER_LENGTH36 &&
            IS_INCLUDE_NON_ALPHANUMERIC === false &&
            IS_ONLY_ALPHABET === false &&
            IS_ONLY_NUMBER === false ? true : false;
        return result;
    }
    isLogined() {
        return this.UID ? true : false;
    }
    downloadExpiringCookie() {
        return __awaiter(this, void 0, void 0, function* () {
            __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___tellTips).call(this, "downloadData");
            const DB_REF_DATA = ref(this.DB, `${this.UID}/cookie`);
            try {
                const snapshot = yield get(DB_REF_DATA);
                if (snapshot.exists()) {
                    const JSON_DATA = snapshot.val();
                    if (typeof (JSON_DATA) == "string") {
                        var parsedData = JSON.parse(JSON_DATA);
                    }
                    else {
                        var parsedData = JSON_DATA;
                    }
                    let EXPIRE_DATE = new Date(parsedData[0]);
                    let CURRENT_DATE = new Date();
                    let ELAPSED_MS_TIME = EXPIRE_DATE.getTime() - CURRENT_DATE.getTime();
                    if (ELAPSED_MS_TIME > 0) {
                        __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___uploadAndResetInfo).call(this);
                        const DICT_DATA = parsedData[1];
                        return DICT_DATA;
                    }
                    else {
                        this.uploadData("data/info", `Cookieの有効期限が切れています。
有効期限：EXPIRE_DATE
現在時刻：18
時差：${ELAPSED_MS_TIME / 1000}秒`);
                        yield new Promise(resolve => setTimeout(resolve, 2000));
                        return false;
                    }
                }
                else {
                    console.log('No data available');
                    return null;
                }
            }
            catch (error) {
                error += "   \nin download Expiring cookie";
                __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___alertMessage).call(this, error);
                console.error('Error getting data:', error);
                throw error;
            }
        });
    }
    downloadData(rawPath) {
        return __awaiter(this, void 0, void 0, function* () {
            __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___tellTips).call(this, "downloadData");
            const RETRY_COUNT_UPTO = 3;
            for (let retry = 0; retry <= RETRY_COUNT_UPTO; retry++) {
                try {
                    const USER_PATH = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
                    const DB_REF_DATA = ref(this.DB, USER_PATH);
                    const snapshot = yield get(DB_REF_DATA);
                    if (snapshot.exists()) {
                        const JSON_DATA = snapshot.val();
                        if (typeof (JSON_DATA) == "string") {
                            var parsedData = JSON.parse(JSON_DATA);
                        }
                        else {
                            var parsedData = JSON_DATA;
                        }
                        if (Array.isArray(parsedData)) {
                            if (parsedData.length > 0 && parsedData[0] === "json") {
                                parsedData = parsedData[1];
                            }
                        }
                        return parsedData;
                    }
                    else {
                        console.log('No data available');
                        return null;
                    }
                }
                catch (error) {
                    if (retry == RETRY_COUNT_UPTO) {
                        if (this.ACCOUNT_DATA.uid) {
                            error += `   \nin download data and uid is ${this.ACCOUNT_DATA.uid}`;
                            __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___alertMessage).call(this, error);
                            console.error('Error getting data:', error);
                            throw error;
                        }
                        else {
                            return;
                        }
                    }
                    else {
                        console.log(`In download method, error happend, Retry 2sec later...(${retry})`);
                        yield this.UtilsFunc.sleep(2000, { preloder: "charWaterflow" });
                    }
                }
            }
        });
    }
    loginSystem(LoginSystemArgs) {
        return __awaiter(this, void 0, void 0, function* () {
            const IS_LOGINED = yield __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___isLogined).call(this);
            var signResult = "";
            if (IS_LOGINED.isLogined) {
                signResult = __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___logoutFromGoogle).call(this, LoginSystemArgs);
            }
            else {
                signResult = __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___loginWithGoogle).call(this, LoginSystemArgs);
            }
            return signResult;
        });
    }
    renderAuthStatus(ARGS) {
        return __awaiter(this, void 0, void 0, function* () {
            if (ARGS.METHOD === "signInWithPopup") {
                const LOGIN_SYSTEM_ARGS = {
                    HTML_BTN_ELEMENT: ARGS.HTML_BTN_ELEMENT,
                    SPAN_NAME: ARGS.SPAN_NAME,
                    isRedirect: false,
                    CALL_FROM: "in FirebaseFunction, renderAuthStatus, signInWithPopup"
                };
                const RESULT = yield __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___loginWithGoogle).call(this, LOGIN_SYSTEM_ARGS);
                return RESULT;
            }
            else if (ARGS.METHOD === "onAuthStateChanged") {
                const AUTH_DATA = yield __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___isLogined).call(this);
                const RESULT = __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___applyByAuthStateChange).call(this, ARGS, AUTH_DATA);
                return RESULT;
            }
            else if (ARGS.METHOD === "signInWithRedirect") {
                const RESULT = __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___applyBySignInWithRedirect).call(this);
            }
        });
    }
    doIfThereRedirectResult(ARGS) {
        return __awaiter(this, void 0, void 0, function* () {
            const REDIRECT_RESULT = yield getRedirectResult(this.AUTH);
            if (REDIRECT_RESULT) {
                ARGS.HTML_BTN_ELEMENT.textContent = "ログアウト";
                ARGS.SPAN_NAME.textContent = `${REDIRECT_RESULT.user.displayName}さん　ようこそ`;
                ARGS.SPAN_NAME.style.display = "block";
                this.UID = REDIRECT_RESULT.user.uid;
                this.ACCOUNT_DATA = REDIRECT_RESULT.user;
                this.ACCESS_TOKEN = REDIRECT_RESULT._tokenResponse.oauthAccessToken;
                return true;
            }
            else {
                return false;
            }
        });
    }
    deleteDataPath(rawPath) {
        const USER_PATH = this.IS_LOGIN_REQUIRED ? `${this.UID}/${rawPath}` : `${rawPath}`;
        const DB_REF_DATA = ref(this.DB, USER_PATH);
        remove(DB_REF_DATA);
    }
}
_FirebaseFunctions_instances = new WeakSet(), _FirebaseFunctions___loginWithGoogle = function _FirebaseFunctions___loginWithGoogle(LoginSystemArgs) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const result = yield signInWithPopup(this.AUTH, this.PROVIDER);
            LoginSystemArgs.HTML_BTN_ELEMENT.textContent = "ログアウト";
            LoginSystemArgs.SPAN_NAME.textContent = `${result.user.displayName}さん　ようこそ`;
            LoginSystemArgs.SPAN_NAME.style.display = "block";
            this.UID = result.user.uid;
            this.ACCOUNT_DATA = result.user;
            this.ACCESS_TOKEN = result._tokenResponse.oauthAccessToken;
            this.uploadData("/refreshToken", result._tokenResponse.refreshToken);
            if (LoginSystemArgs.isRedirect && LoginSystemArgs.REDIRECT_METHOD && LoginSystemArgs.CALL_FROM) {
                new UrlFunction().redirect({
                    METHOD: LoginSystemArgs.REDIRECT_METHOD,
                    CALL_FROM: LoginSystemArgs.CALL_FROM,
                    QUERY: LoginSystemArgs.QUERY
                });
            }
            return true;
        }
        catch (error) {
            alert(error);
            __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___translateSignErrors).call(this, error.message);
            return false;
        }
    });
}, _FirebaseFunctions___logoutFromGoogle = function _FirebaseFunctions___logoutFromGoogle(LoginSystemArgs) {
    signOut(this.AUTH).then(() => {
        LoginSystemArgs.HTML_BTN_ELEMENT.textContent = "ログイン";
        LoginSystemArgs.SPAN_NAME.textContent = "";
        LoginSystemArgs.SPAN_NAME.style.display = "none";
        this.UID = "";
        this.ACCOUNT_DATA = {};
        this.uploadData("/token", "");
        if (LoginSystemArgs.isRedirect && LoginSystemArgs.REDIRECT_METHOD && LoginSystemArgs.CALL_FROM) {
            new UrlFunction().redirect({
                METHOD: LoginSystemArgs.REDIRECT_METHOD,
                CALL_FROM: LoginSystemArgs.CALL_FROM,
                QUERY: LoginSystemArgs.QUERY
            });
        }
        return true;
    }).catch((error) => {
        alert(error);
        __classPrivateFieldGet(this, _FirebaseFunctions_instances, "m", _FirebaseFunctions___translateSignErrors).call(this, error.message);
        return false;
    });
}, _FirebaseFunctions___isLogined = function _FirebaseFunctions___isLogined() {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            onAuthStateChanged(this.AUTH, (result) => __awaiter(this, void 0, void 0, function* () {
                if (result) {
                    resolve({ isLogined: true, accountData: result });
                }
                else {
                    resolve({ isLogined: false, accountData: null });
                }
            }));
        });
    });
}, _FirebaseFunctions___applyByAuthStateChange = function _FirebaseFunctions___applyByAuthStateChange(ARGS, AUTH_DATA) {
    if (AUTH_DATA.isLogined) {
        ARGS.HTML_BTN_ELEMENT.textContent = "ログアウト";
        ARGS.SPAN_NAME.textContent = `${AUTH_DATA.accountData.displayName}さん　ようこそ`;
        ARGS.SPAN_NAME.style.display = "block";
        this.UID = AUTH_DATA.accountData.uid;
        this.ACCOUNT_DATA = AUTH_DATA.accountData;
        return true;
    }
    else {
        ARGS.HTML_BTN_ELEMENT.textContent = "ログイン";
        ARGS.SPAN_NAME.textContent = "";
        return false;
    }
}, _FirebaseFunctions___applyBySignInWithRedirect = function _FirebaseFunctions___applyBySignInWithRedirect() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield signInWithRedirect(this.AUTH, this.PROVIDER);
        }
        catch (error) {
            alert(`in FirebaseFunctions, renderAuthStatus, __applyBySignInWithRedirect. ログインエラーです。`);
        }
    });
}, _FirebaseFunctions___translateSignErrors = function _FirebaseFunctions___translateSignErrors(RAW_ERROR_MESSAGE) {
    const match = RAW_ERROR_MESSAGE.match(/([^)]+)/);
    const EXTRACTED_MESSAGE = match ? match[1] : RAW_ERROR_MESSAGE;
    const RECORD_ERROR_MESSAGE = {
        "auth/popup-closed-by-user": "ポップアップを閉じられました。認証が未完了です。もう一度認証してください。",
        "auth/cancelled-popup-request": "すでにほかのポップアップが出ています。以前のポップアップを閉じてください。",
        "auth/popup-blocked": "ブラウザがポップアップをブロックしました。ブラウザの設定でポップアップを許可してください。",
        "auth/operation-not-allowed": "Google認証が有効になっていません。開発者にFirebase Authenticationを確認するよう問い合わせてください。",
        "auth/invalid-credential": "有効期限が切れています。もう一度認証してください。",
        "auth/user-disabled": "Firebaseでユーザーアカウントが無効化されています。開発者にユーザーアカウント名を教えてください。",
        "auth/wrong-password": "パスワードが間違っています。",
        "auth/network-request-failed": "ネットワークエラーです。ネット接続を確認して、再試行してください。",
        "auth/too-many-requests": "短期間に何度もログインされたため、一時的にブロックされています。時間をおいてからお試しください。",
        "auth/timeout": "ネットワークエラーです。ネット接続を確認して、再試行してください。"
    };
    if (EXTRACTED_MESSAGE in RECORD_ERROR_MESSAGE) {
        alert(RECORD_ERROR_MESSAGE[EXTRACTED_MESSAGE]);
    }
    else {
        alert("サインイン・アウト時に予期せぬエラーが生じました。");
    }
}, _FirebaseFunctions___fetchGoogleAccountData = function _FirebaseFunctions___fetchGoogleAccountData() {
    onAuthStateChanged(this.AUTH, (user) => {
        if (user) {
            return user;
        }
        else {
            alert("Error:未ログイン状態でFirebaseFunctions, #__fetchGoogleAccountDataが実行されました。");
        }
    });
}, _FirebaseFunctions___uploadAndResetInfo = function _FirebaseFunctions___uploadAndResetInfo() {
    this.uploadData("data/info", "");
}, _FirebaseFunctions___alertMessage = function _FirebaseFunctions___alertMessage(INFO) {
    alert(`Error: yamatoaita@gmail.comにこの文章をお知らせください。
Error info : ${INFO}`);
}, _FirebaseFunctions___initTipFlg = function _FirebaseFunctions___initTipFlg() {
    this.isShowTip = {
        "downloadData": true
    };
}, _FirebaseFunctions___tellTips = function _FirebaseFunctions___tellTips(METHOD) {
    const GREEN = "color:green";
    const RED = "color:red";
    const BLUE = "color:blue";
    const NORMAL = "color:black;font-weight:normal";
    const BOLD = "font-weight:bold`";
    if (METHOD == "downloadData" && this.isShowTip["downloadData"]) {
        this.isShowTip["downloadData"] = false;
        console.log(`
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
    `, `GREEN;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `GREEN;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `GREEN;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`, `BLUE;BOLD`, `NORMAL`);
    }
}, _FirebaseFunctions___showCaution = function _FirebaseFunctions___showCaution(FUNCTION_NAME, ITEM) {
    var stack;
    const ERROR = new Error();
    if (ERROR.stack) {
        stack = ERROR.stack.replace("Error", "");
        stack = stack.replace(/^\s*at FirebaseFunctions.*$/gm, "");
        if (FUNCTION_NAME == "uploadExpiringCookie") {
            alert(`注意 : アップロードしようとしているものはDictionary型ではありません。

    uploadExpiringCookie関数は仕様上、Dictionary型を渡すことを推奨します。

    渡された値：ITEM   データ型：${typeof (ITEM)}

    現在の行番号：stack`);
        }
    }
};
const PRELOADER_OPTIONS = ["charWaterflow"];
const SUBTRACT_DATE_OPTIONS = ["month", "week", "day", "hour"];
const WEEKDAY_OPTIONS = ["long", "short"];
const MONTH_OPTIONS = ["numeric", "2-digit", "long", "short"];
class UtilsFunctions {
    constructor() {
    }
    sleep(MS, PRELOADER, PRELOADER_OPTION) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log(`注意事項\nsleepを使う際は使用する関数にasyncをつけ、await sleepとして使います。`);
            if (PRELOADER && PRELOADER_OPTION) {
                if (PRELOADER_OPTION.preloder === "charWaterflow") {
                    PRELOADER.charWaterflow("SleepTimerMode");
                }
                yield new Promise(resolve => setTimeout(resolve, MS));
                PRELOADER.closePreLoader("SleepTimerMode");
            }
            else {
                yield new Promise(resolve => setTimeout(resolve, MS));
            }
        });
    }
    calcWeekday(MONTH_NUMBER, DATE_NUMBER) {
        if (MONTH_NUMBER >= 0 && DATE_NUMBER >= 0) {
            const CURRENT_YEAR = new Date().getFullYear();
            const CURRENT_MONTH = new Date().getMonth();
            const WEEKDAYS = ["日", "月", "火", "水", "木", "金", "土"];
            var weekdaysIndex = 0;
            if (MONTH_NUMBER >= CURRENT_MONTH) {
                weekdaysIndex = new Date(CURRENT_YEAR, MONTH_NUMBER - 1, DATE_NUMBER).getDay();
            }
            else if (MONTH_NUMBER < CURRENT_MONTH) {
                weekdaysIndex = new Date(CURRENT_YEAR + 1, MONTH_NUMBER - 1, DATE_NUMBER).getDay();
            }
            const WEEKDAY = WEEKDAYS[weekdaysIndex];
            return WEEKDAY;
        }
        else {
            const STACK = new Error();
            alert(`${MONTH_NUMBER}月${DATE_NUMBER}日は無効な値です。引数を確かめてください。\n${STACK.message}`);
        }
    }
    subtractDates(OPTION) {
        const DATE = new Date(OPTION.targetDate);
        if (OPTION.timeUnit === "month") {
            DATE.setMonth(DATE.getMonth() - OPTION.minusAmount);
        }
        else if (OPTION.timeUnit === "week") {
            DATE.setDate(DATE.getDate() - OPTION.minusAmount * 7);
        }
        else if (OPTION.timeUnit === "day") {
            DATE.setDate(DATE.getDate() - OPTION.minusAmount);
        }
        else if (OPTION.timeUnit === "hour") {
            DATE.setHours(DATE.getHours() - OPTION.minusAmount);
        }
        return DATE;
    }
    toHarfWidthDegitText(FULL_WIDTH_DIGIT) {
        const HARF_WIDTH_DEGIT_STRING = FULL_WIDTH_DIGIT.replace(/[０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0));
        return HARF_WIDTH_DEGIT_STRING;
    }
    getLuminance(COLOR) {
        var r;
        var g;
        var b;
        if (COLOR.match(/#[a-z0-9]+/g)) {
            r = parseInt(COLOR.slice(1, 3), 16) / 255;
            g = parseInt(COLOR.slice(3, 5), 16) / 255;
            b = parseInt(COLOR.slice(5, 7), 16) / 255;
        }
        else {
            const RAW_STRING = COLOR.replace(/[()rgb]/g, "");
            const COLOR_INDEXS = RAW_STRING.split(",");
            r = parseInt(COLOR_INDEXS[0]) / 255;
            g = parseInt(COLOR_INDEXS[1]) / 255;
            b = parseInt(COLOR_INDEXS[2]) / 255;
        }
        const LUM = (channel) => {
            return (channel <= 0.03928) ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
        };
        const LUMINANCE = 0.2126 * LUM(r) + 0.7152 * LUM(g) + 0.0722 * LUM(b);
        return LUMINANCE;
    }
    chooseSuitableFontColor(BACKGROUND_COLOR) {
        const LUMINANCE = this.getLuminance(BACKGROUND_COLOR);
        var fontColor = "";
        if (LUMINANCE <= 0.3) {
            fontColor = "#FFFFFF";
        }
        else {
            fontColor = "#000000";
        }
        return fontColor;
    }
    changeRGBtoColorCode(RGB) {
        if (RGB.match(/^rgb/)) {
            const REPLACED_RGB = RGB.replace(/[rgba()]+/g, "");
            const RGB_ELEMENTS = REPLACED_RGB.split(",");
            const R = parseInt(RGB_ELEMENTS[0]);
            const G = parseInt(RGB_ELEMENTS[1]);
            const B = parseInt(RGB_ELEMENTS[2]);
            const toColorCode = (value) => value.toString(16).padStart(2, "0");
            const COLOR_CODE = `#${toColorCode(R)}${toColorCode(G)}${toColorCode(B)}`.toUpperCase();
            return COLOR_CODE;
        }
        else {
            alert(`引数の${RGB}はRGBコードではありません。rgb(000,000,000)またはrgba(000,000,000)の形式のコードを渡してください`);
        }
    }
    changeColorCodeToRGB(COLOR_CODE) {
        if (COLOR_CODE.match(/^#/)) {
            const R = parseInt(COLOR_CODE.slice(1, 3), 16);
            const G = parseInt(COLOR_CODE.slice(3, 5), 16);
            const B = parseInt(COLOR_CODE.slice(5, 7), 16);
            const RGB = `rgb(${R}, ${G}, ${B})`;
            return RGB;
        }
        else {
            alert(`引数の${COLOR_CODE}は１６進数のカラーコードではありません。#000000の形式のコードを渡してください。`);
        }
    }
    deleteListElem(LIST, ELEM) {
        const INDEX = LIST.indexOf(ELEM);
        if (INDEX === -1) {
            alert(`引数の要素:「${ELEM}」はlistにありませんでした。`);
            console.table(LIST);
        }
        else {
            const NEW_LIST = LIST.filter((item) => {
                if (item === ELEM) {
                    return false;
                }
                else {
                    return true;
                }
            });
            return NEW_LIST;
        }
    }
    formatDate(iso_date, options) {
        const JP_DATE = new Date(new Date(iso_date).getTime());
        const ISO8601_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{3})?Z?$/;
        if (ISO8601_PATTERN.test(iso_date)) {
        }
        else {
            alert("UtilsFunc, formatDateの引数 iso_dateはISO8061形式にしてください。");
            return "";
        }
        const OPTION_RECORD = { timeZone: "UTC" };
        if (options.showYear) {
            OPTION_RECORD.year = "numeric";
        }
        if (options.showMonth) {
            OPTION_RECORD.month = options.monthOption;
        }
        if (options.showDay) {
            OPTION_RECORD.day = "numeric";
        }
        if (options.showHour) {
            OPTION_RECORD.hour = "numeric";
        }
        if (options.showMinute) {
            OPTION_RECORD.minute = "numeric";
        }
        if (options.showSecond) {
            OPTION_RECORD.second = "numeric";
        }
        if (options.showWeekday) {
            OPTION_RECORD.weekday = options.weekdayOption;
        }
        if (options.isHour12) {
            OPTION_RECORD.hour12 = true;
        }
        else {
            OPTION_RECORD.hour12 = false;
        }
        return JP_DATE.toLocaleString(undefined, OPTION_RECORD);
    }
    formatDateDifference(iso_startDate, iso_endDate, options) {
        var startDate = new Date(new Date(iso_startDate).getTime());
        var endDate = new Date(new Date(iso_endDate).getTime());
        let diff = endDate.getTime() - startDate.getTime();
        var year = 0;
        var month = 0;
        var week = 0;
        var day = 0;
        var hour = 0;
        var minute = 0;
        var second = 0;
        if (options.showYear) {
            year = Math.floor(diff / (365 * 24 * 60 * 60 * 1000));
            diff -= year * (365 * 24 * 60 * 60 * 1000);
        }
        if (options.showMonth) {
            month = Math.floor(diff / (30 * 24 * 60 * 60 * 1000));
            diff -= month * (30 * 24 * 60 * 60 * 1000);
        }
        if (options.showWeek) {
            week = Math.floor(diff / (7 * 24 * 60 * 60 * 1000));
            diff -= week * (7 * 24 * 60 * 60 * 1000);
        }
        if (options.showDay) {
            day = Math.floor(diff / (24 * 60 * 60 * 1000));
            diff -= day * (24 * 60 * 60 * 1000);
        }
        if (options.showHour) {
            hour = Math.floor(diff / (60 * 60 * 1000));
            diff -= hour * (60 * 60 * 1000);
        }
        if (options.showMinute) {
            minute = Math.floor(diff / (60 * 1000));
            diff -= minute * (60 * 1000);
        }
        if (options.showSecond) {
            second = Math.floor(diff / 1000);
        }
        return `${year === 0 ? "" : `${year}年`} ${month === 0 ? "" : `${month}ヵ月`} ${week === 0 ? "" : `${week}週間`} ${day === 0 ? "" : `${day}日`} ${hour === 0 ? "" : `${hour}時間`} ${minute === 0 ? "" : `${minute}分`} ${second === 0 ? "" : `${second}秒`}`;
    }
    provideRandomID() {
        return self.crypto.randomUUID();
    }
}
class UrlFunction {
    constructor() {
        _UrlFunction_instances.add(this);
    }
    extractHtmlTitle(rawHtml, CALL_FROM) {
        const url = new URL(rawHtml);
        let htmlLink = url.pathname;
        htmlLink = htmlLink.replace(/\/$/, "");
        var configured_item = htmlLink.split("/").pop();
        if (configured_item) {
            const MATCHED_ITEMS = configured_item.match(/^(.+)(?:\.github\.io|\.html)?\/?$/);
            if (MATCHED_ITEMS) {
                var htmlTitle = MATCHED_ITEMS[1];
                htmlTitle = htmlTitle.replace(".html", "");
                htmlTitle = htmlTitle.replace(/\?.*$/, "");
                return htmlTitle;
            }
            else {
                alert(`Error: Utils.js, UrlFunction, extractHtmlTitle, 正規表現に一致しませんでした。htmlLink is ${htmlLink}, Reg is ^(.+)(?:\.github\.io|\.html)?\/?$\ncall from ${CALL_FROM}`);
            }
        }
        else {
            alert(`Error: Utils.js, UrlFunction, extractHtmlTitle, configured_item is undefined. htmlLink is ${htmlLink}\ncall from ${CALL_FROM}`);
        }
    }
    __deleteQueryPart(URL) {
        const URL_COMPONENTS = URL.split("?");
        if (URL_COMPONENTS.length > 1) {
            return URL_COMPONENTS[0];
        }
        else {
            return URL;
        }
    }
    redirect(REDIRECT_DATA) {
        if (REDIRECT_DATA.METHOD === "toSelectedPage") {
            if (REDIRECT_DATA.PAGE_TITLE) {
                var url = __classPrivateFieldGet(this, _UrlFunction_instances, "m", _UrlFunction___composeURLbyPageTitle).call(this, REDIRECT_DATA.PAGE_TITLE, REDIRECT_DATA.CALL_FROM);
                if (REDIRECT_DATA.QUERY) {
                    let query = this.__convertDataToQueryString(REDIRECT_DATA.QUERY);
                    url += `?data=${query}`;
                }
                if (url) {
                    window.location.href = url;
                }
                else {
                    this.alertError("composeURLbyPageTitle", `${REDIRECT_DATA.CALL_FROM}, 無効なURLでした。URL:${window.location.href}`);
                }
            }
            else {
                alert(`in UrlFunction, redirect. composeURLbyPageTitleが引数に渡されました。しかし、必要なPAGE_TITLEが引数にありません。指定してください。\ncall from`);
            }
        }
        else if (REDIRECT_DATA.METHOD === "toHP") {
            var url = __classPrivateFieldGet(this, _UrlFunction_instances, "m", _UrlFunction___returnHomePageURL).call(this, REDIRECT_DATA.CALL_FROM, "index");
            if (REDIRECT_DATA.QUERY) {
                let query = this.__convertDataToQueryString(REDIRECT_DATA.QUERY);
                url += `?data=${query}`;
            }
            if (url) {
                window.location.href = url;
            }
            else {
                this.alertError("returnHomePageURL", `${REDIRECT_DATA.CALL_FROM}, 無効なURLでした。URL:${window.location.href}`);
            }
        }
    }
    __convertDataToQueryString(DATA) {
        var query_string = "";
        if (typeof (DATA) === "object") {
            query_string = encodeURIComponent(JSON.stringify(DATA));
        }
        else {
            query_string = DATA;
        }
        return `${query_string}`;
    }
    extractQuery() {
        const URL_PARAMS = new URLSearchParams(window.location.search);
        const QUERY_VALUE = URL_PARAMS.get(`data`);
        if (QUERY_VALUE) {
            try {
                const PARSED_DATA = JSON.parse(QUERY_VALUE);
                return PARSED_DATA;
            }
            catch (e) {
                return QUERY_VALUE;
            }
        }
        else {
            console.log("URLFUNCTION: extractQuery: クエリパラメータ 'data' は存在しません。");
            return "";
        }
    }
    alertError(METHOD_NAME, INFO) {
        alert(`Error: in UrlFunction, ${METHOD_NAME}, ${INFO}`);
        console.log(`Error: in UrlFunction, ${METHOD_NAME}, ${INFO}`);
    }
}
_UrlFunction_instances = new WeakSet(), _UrlFunction___composeURLbyPageTitle = function _UrlFunction___composeURLbyPageTitle(PAGE_TITLE, CALL_FROM, URL = window.location.href) {
    const PAGE_TITLE_REG_WITH_SYNBOLE = /\/([a-zA-Z0-9_.・},@%]*)\.html$/;
    URL = this.__deleteQueryPart(URL);
    if (URL.match(/github/)) {
        const MATCHED_ITEMS = URL.match(/https:\/{2}syuubunndou.github.io\/[/w/.]*/);
        if (MATCHED_ITEMS) {
            const FUNDATIONAL_URL = MATCHED_ITEMS[0];
            if (URL.match(/\.html$/)) {
                const IS_MATCH = URL.match(PAGE_TITLE_REG_WITH_SYNBOLE) ? true : false;
                if (IS_MATCH) {
                    var composedURL = URL.replace(PAGE_TITLE_REG_WITH_SYNBOLE, `/${PAGE_TITLE}.html`);
                    return composedURL;
                }
                else {
                    alert(`ファイル名エラーです。htmlファイル名にひらがなや漢字が含まれていませんか？ url : ${URL}`);
                }
            }
            else {
                var composedURL = `${URL}${PAGE_TITLE}.html`;
                return composedURL;
            }
        }
        else {
            alert(`Error: Utils.js, UrlFunctions, composedURLbyPageTitle, 正規表現にマッチしたものはありません。URL is ${URL} \ncall from${CALL_FROM}`);
            return;
        }
    }
    else {
        console.log(`url  : ${URL}`);
        const IS_MATCH = URL.match(PAGE_TITLE_REG_WITH_SYNBOLE) ? true : false;
        if (IS_MATCH) {
            var composedURL = URL.replace(PAGE_TITLE_REG_WITH_SYNBOLE, `/${PAGE_TITLE}\.html`);
            return composedURL;
        }
        else {
            alert(`ファイル名エラーです。htmlファイル名にひらがなや漢字が含まれていませんか？ url : ${URL} \ncall from${CALL_FROM}`);
        }
    }
}, _UrlFunction___returnHomePageURL = function _UrlFunction___returnHomePageURL(CALL_FROM, homePageTitle = "index") {
    const URL = this.__deleteQueryPart(window.location.href);
    if (URL.match(/github/)) {
        const MATCHED_ITEMS = URL.match(/https:\/{2}syuubunndou.github.io\/[\w\.]*\//);
        if (MATCHED_ITEMS) {
            var gitHomePageURL = MATCHED_ITEMS[0];
            return gitHomePageURL;
        }
        else {
            alert(`Error: Utils.js, UrlFunction, returnHomePageURL, 正規表現にマッチしたものはありません。 URL is : ${URL}\ncall from${CALL_FROM}`);
            return;
        }
    }
    else {
        var localHomePageURL = __classPrivateFieldGet(this, _UrlFunction_instances, "m", _UrlFunction___composeURLbyPageTitle).call(this, homePageTitle, CALL_FROM, URL);
        return localHomePageURL;
    }
};
const VALIDATION_OPTIONS = ["lengthWithin",
    "onlyNumbers",
    "onlySelectedNumberRange",
    "zeroPadding",
    "withinMonthlyDate",
    "renderWeekday"];
class HtmlFunction {
    constructor() {
        _HtmlFunction_instances.add(this);
        this.UtilsFunc = new UtilsFunctions();
        this.debounceTime = 50;
        this.lastLaunchTimes = {};
        this.PLACEHOLDER_ELEM = "";
        this._boundResetPlaceHolder = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___resetPlaceHolder).bind(this);
    }
    setPlaceHolder(CONTENT_ELEMENT, PLACE_HOLDER_TEXT) {
        if (this.PLACEHOLDER_ELEM) {
            console.log("ヒント：setPlaceHolderを使用するときには\nnew HtmlFunction()で毎回インスタンスを生成してください。");
        }
        if (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement) {
            CONTENT_ELEMENT.innerHTML = PLACE_HOLDER_TEXT;
        }
        else if (CONTENT_ELEMENT instanceof HTMLInputElement) {
            CONTENT_ELEMENT.value = PLACE_HOLDER_TEXT;
        }
        CONTENT_ELEMENT.style.color = "rgb(153, 153, 153)";
        CONTENT_ELEMENT.addEventListener("focus", this._boundResetPlaceHolder, { once: true });
        this.PLACEHOLDER_ELEM = CONTENT_ELEMENT;
    }
    deletePlaceholderEvent() {
        this.PLACEHOLDER_ELEM.removeEventListener("focus", this._boundResetPlaceHolder);
        this.PLACEHOLDER_ELEM.style.color = "rgb(0, 0, 0)";
        this.PLACEHOLDER_ELEM.focus();
    }
    setUnfilledSignifier(CONTENT_ELEMENT) {
        CONTENT_ELEMENT.style.backgroundColor = "rgb(255, 208, 0)";
        CONTENT_ELEMENT.addEventListener("focus", () => {
            CONTENT_ELEMENT.style.backgroundColor = "rgb(255,255,255)";
        }, { once: true });
    }
    setValidation(VALIDATION_DATA) {
        const OPTIONS = VALIDATION_DATA.VALIDATE_OPTION;
        for (let option of OPTIONS) {
            for (let element of VALIDATION_DATA.CONTENT_ELEMENTS) {
                if (option === "lengthWithin") {
                    if (VALIDATION_DATA.LENGTH) {
                        __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___validateLengthWithin).call(this, element, VALIDATION_DATA.LENGTH);
                    }
                    else {
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数LENGTHがありません。`);
                        break;
                    }
                }
                else if (option === "onlyNumbers") {
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___onlyNumbers).call(this, element);
                }
                else if (option === "onlySelectedNumberRange") {
                    if (typeof VALIDATION_DATA.MAX_NUMBER === "number" && typeof VALIDATION_DATA.MIN_NUMBER === "number") {
                        __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___onlySelectedNumberRange).call(this, element, VALIDATION_DATA.MIN_NUMBER, VALIDATION_DATA.MAX_NUMBER);
                    }
                    else {
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数MIN_NUMBERとMAX_NUMBERがそろっていません。`);
                        break;
                    }
                }
                else if (option === "zeroPadding") {
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___zeroPadding).call(this, element);
                }
                else if (option === "withinMonthlyDate") {
                    if (VALIDATION_DATA.MONTH_ELEMENT) {
                        __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___withinMonthlyDate).call(this, element, VALIDATION_DATA.MONTH_ELEMENT);
                    }
                    else {
                        const STACK = new Error().stack;
                        alert(`Error: ${STACK},\n必要な引数MONTH_ELEMENTがありません。`);
                        break;
                    }
                }
                else if (option === "renderWeekday") {
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___renderWeekday).call(this, element, VALIDATION_DATA.MONTH_ELEMENT, VALIDATION_DATA.DATE_ELEMENT);
                }
            }
        }
    }
    alignSpanToAdjacentInputCenter(TARGET_SPAN, INPUT_SPAN) {
        const TARGET_SPAN_STYLE = window.getComputedStyle(TARGET_SPAN);
        const FIRST_TARGET_SPAN_TOP = TARGET_SPAN_STYLE.top;
        INPUT_SPAN.addEventListener("input", () => {
            const INPUT_SPAN_STYLE = window.getComputedStyle(INPUT_SPAN);
            const INPUT_FONT_SIZE = parseInt(INPUT_SPAN_STYLE.fontSize);
            const BASED_LINE_HEIGHT = Math.round(1.485 * INPUT_FONT_SIZE + 0.587);
            const LINE_HEIGHT = INPUT_FONT_SIZE * 0.7;
            const INPUT_SPAN_HEIGHT = INPUT_SPAN_STYLE.height.replace("px", "");
            const LINES = Math.round(INPUT_SPAN_HEIGHT / BASED_LINE_HEIGHT);
            TARGET_SPAN.style.top = FIRST_TARGET_SPAN_TOP;
            TARGET_SPAN.style.top = `${parseInt(TARGET_SPAN_STYLE.top.replace("px", "")) - LINE_HEIGHT * LINES + parseInt(FIRST_TARGET_SPAN_TOP.replace("px", "")) * 2 - 13}px`;
        });
    }
    provideUniqueID() {
        const DATE_RND_ID = `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8).padEnd(6, "0")}`;
        const CRYPTO_ID = crypto.getRandomValues(new Uint32Array(1))[0].toString(16).padStart(8, "0");
        const MIXED_ID = `${DATE_RND_ID}-${CRYPTO_ID}`;
        return MIXED_ID;
    }
    changeImage(IMAGE_ELEMENT, NEW_IMAGE_SRC) {
        const PARENT_PATH = IMAGE_ELEMENT.src.substring(0, IMAGE_ELEMENT.src.lastIndexOf("/") + 1);
        const NEW_FULL_PATH = `${PARENT_PATH}${NEW_IMAGE_SRC}`;
        IMAGE_ELEMENT.src = NEW_FULL_PATH;
    }
}
_HtmlFunction_instances = new WeakSet(), _HtmlFunction___resetPlaceHolder = function _HtmlFunction___resetPlaceHolder() {
    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, this.PLACEHOLDER_ELEM, "");
    this.PLACEHOLDER_ELEM.style.color = "rgb(0, 0, 0)";
    this.PLACEHOLDER_ELEM.focus();
}, _HtmlFunction___getRawText = function _HtmlFunction___getRawText(CONTENT_ELEMENT) {
    var rawText = "";
    if (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement) {
        rawText = CONTENT_ELEMENT.textContent;
    }
    else if (CONTENT_ELEMENT instanceof HTMLInputElement) {
        rawText = CONTENT_ELEMENT.value;
    }
    return rawText;
}, _HtmlFunction___setValueToContentElement = function _HtmlFunction___setValueToContentElement(CONTENT_ELEMENT, VALUE) {
    if (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement) {
        CONTENT_ELEMENT.textContent = VALUE;
    }
    else if (CONTENT_ELEMENT instanceof HTMLInputElement) {
        CONTENT_ELEMENT.value = VALUE;
    }
}, _HtmlFunction___validateLengthWithin = function _HtmlFunction___validateLengthWithin(CONTENT_ELEMENT, LENGTH) {
    CONTENT_ELEMENT.addEventListener("input", () => {
        var text = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
        var textLength;
        if (text) {
            textLength = text.length;
            if (textLength > LENGTH) {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, text.slice(0, -1));
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setCursorToEnd).call(this, CONTENT_ELEMENT);
            }
            else {
                return;
            }
        }
        else {
            return;
        }
    });
}, _HtmlFunction___setCursorToEnd = function _HtmlFunction___setCursorToEnd(CONTENT_ELEMENT) {
    if (CONTENT_ELEMENT instanceof HTMLDivElement || CONTENT_ELEMENT instanceof HTMLSpanElement) {
        const RANGE = document.createRange();
        const SELECTION = window.getSelection();
        RANGE.selectNodeContents(CONTENT_ELEMENT);
        RANGE.collapse(false);
        SELECTION.removeAllRanges();
        SELECTION.addRange(RANGE);
    }
    else if (CONTENT_ELEMENT instanceof HTMLInputElement) {
        const length = CONTENT_ELEMENT.value.length;
        CONTENT_ELEMENT.setSelectionRange(length, length);
        CONTENT_ELEMENT.focus();
    }
}, _HtmlFunction___onlyNumbers = function _HtmlFunction___onlyNumbers(CONTENT_ELEMENT) {
    this.lastLaunchTimes.onlyNumbers = new Date();
    CONTENT_ELEMENT.addEventListener("input", () => {
        if (__classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___isLaunchEvent).call(this, "onlyNumbers")) {
            const RAW_TEXT = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
            if (RAW_TEXT) {
                const IS_NUM = RAW_TEXT.match(/^[0-9０-９]+$/) ? true : false;
                if (IS_NUM) {
                    var fullWidthDigit = this.UtilsFunc.toHarfWidthDegitText(RAW_TEXT);
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, fullWidthDigit);
                }
                else {
                    alert(`数値以外が入力されたため、文字を消去しました。`);
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, RAW_TEXT.replace(/[^0-9]+/g, ""));
                }
            }
            this.lastLaunchTimes.onlyNumbers = new Date();
        }
        else {
            const RAW_TEXT = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
            if (RAW_TEXT) {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, RAW_TEXT.replace(/[^0-9]/g, ""));
                return;
            }
        }
    });
}, _HtmlFunction___onlySelectedNumberRange = function _HtmlFunction___onlySelectedNumberRange(CONTENT_ELEMENT, MIN_NUMBER, MAX_NUMBER) {
    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___onlyNumbers).call(this, CONTENT_ELEMENT);
    var text_number;
    var number;
    CONTENT_ELEMENT.addEventListener("input", () => {
        text_number = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
        if (text_number) {
            number = parseInt(text_number);
            if (MIN_NUMBER <= number && number <= MAX_NUMBER) {
            }
            else {
                if (number === 0) {
                    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, "");
                }
                else {
                    if (isNaN(number)) {
                    }
                    else {
                        alert(`入力しようとされた数値:${number}は範囲外の数値です。\n値は${MIN_NUMBER}～${MAX_NUMBER}を入力してください。`);
                        __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, "");
                    }
                }
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setCursorToEnd).call(this, CONTENT_ELEMENT);
            }
        }
        else {
        }
    });
}, _HtmlFunction___withinMonthlyDate = function _HtmlFunction___withinMonthlyDate(CONTENT_ELEMENT, MONTH_ELEMENT) {
    __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___onlyNumbers).call(this, CONTENT_ELEMENT);
    CONTENT_ELEMENT.addEventListener("input", () => {
        var monthString = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, MONTH_ELEMENT);
        if (monthString) {
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___validateMonthlyDate).call(this, CONTENT_ELEMENT, monthString);
        }
        else {
            alert(`月を指定してください`);
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, "");
        }
        ;
    });
    MONTH_ELEMENT.addEventListener("input", () => {
        var monthString = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, MONTH_ELEMENT);
        if (monthString) {
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___validateMonthlyDate).call(this, CONTENT_ELEMENT, monthString);
        }
        else {
        }
    });
}, _HtmlFunction___validateMonthlyDate = function _HtmlFunction___validateMonthlyDate(CONTENT_ELEMENT, monthString) {
    const CURRENT_YEAR = new Date().getFullYear();
    const CURRENT_MONTH = new Date().getMonth();
    var monthNumber = parseInt(monthString);
    var maxDate = 0;
    var taskYear = 2025;
    if (monthNumber >= CURRENT_MONTH) {
        maxDate = new Date(CURRENT_YEAR, monthNumber, 0).getDate();
        taskYear = CURRENT_YEAR;
    }
    else if (monthNumber < CURRENT_MONTH) {
        maxDate = new Date(CURRENT_YEAR + 1, monthNumber, 0).getDate();
        taskYear = CURRENT_YEAR + 1;
    }
    var dayString = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
    var dayNumber;
    if (dayString) {
        dayNumber = parseInt(dayString);
        if (dayNumber) {
            if (0 < dayNumber && dayNumber <= maxDate) {
            }
            else {
                alert(`入力されたのは${dayNumber}日でしたが、${taskYear}年の${monthNumber}月は${maxDate}日までです。`);
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, "");
            }
        }
        else {
            if (dayString == "-") {
            }
            else {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, "01");
            }
        }
    }
    else {
    }
}, _HtmlFunction___zeroPadding = function _HtmlFunction___zeroPadding(CONTENT_ELEMENT) {
    CONTENT_ELEMENT.addEventListener("input", () => {
        var text_number = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, CONTENT_ELEMENT);
        if (text_number) {
            const IS_NUMBER = text_number.match(/^[0-9]+$/) ? true : false;
            if (text_number.length === 1 && IS_NUMBER) {
                text_number = `0${text_number}`;
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, text_number);
            }
            const HEAD_NUMBER = text_number.charAt(0);
            if (HEAD_NUMBER === "0" && text_number.length > 2) {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, text_number.replace(/^0/, ""));
            }
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setCursorToEnd).call(this, CONTENT_ELEMENT);
        }
    });
}, _HtmlFunction___renderWeekday = function _HtmlFunction___renderWeekday(CONTENT_ELEMENT, MONTH_ELEMENT, DATE_ELEMENT) {
    MONTH_ELEMENT.addEventListener("input", () => {
        const MONTH_STRING = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, MONTH_ELEMENT);
        const DATE_STRING = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, DATE_ELEMENT);
        if (MONTH_STRING && DATE_STRING) {
            const MONTH_NUMBER = parseInt(MONTH_STRING);
            const DATE_NUMBER = parseInt(DATE_STRING);
            if (MONTH_NUMBER >= 0 && DATE_NUMBER >= 0) {
                const WEEKDAY = this.UtilsFunc.calcWeekday(MONTH_NUMBER, DATE_NUMBER);
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `(${WEEKDAY})`);
            }
            else {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `()`);
            }
        }
        else {
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `()`);
        }
    });
    DATE_ELEMENT.addEventListener("input", () => {
        const MONTH_STRING = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, MONTH_ELEMENT);
        const DATE_STRING = __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___getRawText).call(this, DATE_ELEMENT);
        if (MONTH_STRING && DATE_STRING) {
            const MONTH_NUMBER = parseInt(MONTH_STRING);
            const DATE_NUMBER = parseInt(DATE_STRING);
            if (MONTH_NUMBER >= 0 && DATE_NUMBER >= 0) {
                const WEEKDAY = this.UtilsFunc.calcWeekday(MONTH_NUMBER, DATE_NUMBER);
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `(${WEEKDAY})`);
            }
            else {
                __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `()`);
            }
        }
        else {
            __classPrivateFieldGet(this, _HtmlFunction_instances, "m", _HtmlFunction___setValueToContentElement).call(this, CONTENT_ELEMENT, `()`);
        }
    });
}, _HtmlFunction___isLaunchEvent = function _HtmlFunction___isLaunchEvent(VALIDATETION_NAME) {
    const CURRENT_TIME = new Date();
    if (VALIDATETION_NAME === "onlyNumbers") {
        const LAST_LAUNCHED_TIME = this.lastLaunchTimes.onlyNumbers;
        const TIME_LAPSE = CURRENT_TIME.getTime() - LAST_LAUNCHED_TIME.getTime();
        return TIME_LAPSE >= this.debounceTime ? true : false;
    }
    else {
        alert(`現在、追加されてないvalidation nameです: ${VALIDATETION_NAME}`);
    }
};
class AnimateFunctions {
    constructor() {
        console.log("ヒント：アニメをつけるElementはdisplay:noneに設定していてください。");
    }
    fadeIn(ELEMENT, SPEED = 0.05) {
        var opacity = 0;
        ELEMENT.style.opacity = opacity.toString();
        ELEMENT.style.display = "block";
        const FADE_EFFECT = setInterval(() => {
            if (opacity < 1) {
                opacity += SPEED;
                ELEMENT.style.opacity = opacity.toString();
            }
            else {
                clearInterval(FADE_EFFECT);
            }
        }, 50);
    }
    fadeOut(ELEMENT, SPEED = 0.05) {
        var opacity = 1;
        const FADE_EFFECT = setInterval(() => {
            if (opacity > 0) {
                opacity -= SPEED;
                ELEMENT.style.opacity = opacity.toString();
            }
            else {
                clearInterval(FADE_EFFECT);
                ELEMENT.style.display = "none";
            }
        }, 50);
    }
}
const CLOSE_SYSTEM = ["SleepTimerMode", "SelfTimerMonitoringMode", "BroadcastMonitoringMode", "SelfCloseMode"];
class PreLoader {
    constructor() {
        _PreLoader_instances.add(this);
        this.PRELOADER_MODAL = document.createElement("div");
        this.PRELOADER_MODAL.className = "preloader";
        this.STYLE = document.createElement("style");
    }
    charWaterflow(CLOSE_SYSTEM_TYPE, FIREBASE_APP = null, PRELOADING_TIME_MS = 0, { BACKGROUND_COLOR = `rgba(0, 0, 0, 0.8)`, ANIMATE_COLOR_PATTERN = [`#0088cc`, `#e23069`, `#F0E300`], BASIC_FONT_COLOR = `rgb(255, 255, 255)` } = {}) {
        document.body.prepend(this.PRELOADER_MODAL);
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
        var basicStyleContext = `
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
        var animateStyleContext = `
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
        this.commonPreloadingSetup(CLOSE_SYSTEM_TYPE, FIREBASE_APP, PRELOADING_TIME_MS);
    }
    boundBalls(CLOSE_SYSTEM_TYPE, FIREBASE_APP = null, PRELOADING_TIME_MS = 0, { BACKGROUND_COLOR = `rgba(0, 0, 0, 0.8)`, FONT_COLOR = `rgb(255, 255, 255)`, LEFT_PX = "0px", DISPLAY_CONTENT = "" } = {}) {
        document.body.prepend(this.PRELOADER_MODAL);
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
        var basicStyleContext = `
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
        this.commonPreloadingSetup(CLOSE_SYSTEM_TYPE, FIREBASE_APP, PRELOADING_TIME_MS);
    }
    commonPreloadingSetup(CLOSE_SYSTEM_TYPE_1) {
        return __awaiter(this, arguments, void 0, function* (CLOSE_SYSTEM_TYPE, FIREBASE_APP = null, PRELOADING_TIME_MS) {
            if (CLOSE_SYSTEM_TYPE === "BroadcastMonitoringMode") {
                if (__classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_isHaveFirebaseApp).call(this, FIREBASE_APP)) {
                }
                else {
                    console.log("in Preloader, mode is Monitor, but you didn't set FirebaseFunctions instance. So, Preloader can't monitor preloading time correctly.");
                }
                __classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_sendStartSignalToFirebase).call(this, FIREBASE_APP);
                __classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_startAutoCloseBroadcastMonitor).call(this, FIREBASE_APP);
            }
            else if (CLOSE_SYSTEM_TYPE === "SleepTimerMode") {
            }
            else if (CLOSE_SYSTEM_TYPE === "SelfTimerMonitoringMode") {
                const START_TIME = Date.now();
                __classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_startAutoCloseSelfTimerMonitor).call(this, START_TIME, PRELOADING_TIME_MS);
            }
            else if (CLOSE_SYSTEM_TYPE === "SelfCloseMode") {
            }
        });
    }
    sendEndSignalToFirebase(FIREBASE_APP) {
        FIREBASE_APP.uploadData(`PreLoader/status`, "readyToClose");
    }
    closePreLoader(CLOSE_SYSTEM_TYPE) {
        return __awaiter(this, void 0, void 0, function* () {
            const AnimateFunc = new AnimateFunctions();
            const UtilsFunc = new UtilsFunctions();
            AnimateFunc.fadeOut(this.PRELOADER_MODAL);
            if (CLOSE_SYSTEM_TYPE === "BroadcastMonitoringMode") {
                this.PRELOADER_MODAL.remove();
                this.STYLE.remove();
            }
            else if (CLOSE_SYSTEM_TYPE === "SleepTimerMode") {
                yield UtilsFunc.sleep(1000, null);
                this.PRELOADER_MODAL.remove();
                this.STYLE.remove();
            }
            else if (CLOSE_SYSTEM_TYPE === "SelfTimerMonitoringMode") {
                this.PRELOADER_MODAL.remove();
                this.STYLE.remove();
            }
            else if (CLOSE_SYSTEM_TYPE === "SelfCloseMode") {
                this.PRELOADER_MODAL.remove();
                this.STYLE.remove();
            }
        });
    }
}
_PreLoader_instances = new WeakSet(), _PreLoader_startAutoCloseSelfTimerMonitor = function _PreLoader_startAutoCloseSelfTimerMonitor(START_TIME, PRELOADING_TIME_MS) {
    const timerId = setInterval(() => __awaiter(this, void 0, void 0, function* () {
        const CAN_BE_CLOSED = __classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_isReadyToCloseSelfTimerPreloader).call(this, START_TIME, PRELOADING_TIME_MS);
        if (CAN_BE_CLOSED) {
            console.log("close");
            clearInterval(timerId);
            yield this.closePreLoader("BroadcastMonitoringMode");
        }
    }), 500);
}, _PreLoader_isReadyToCloseSelfTimerPreloader = function _PreLoader_isReadyToCloseSelfTimerPreloader(START_TIME, PRELOADING_TIME_MS) {
    console.log(`time lapse is  ${Date.now() - START_TIME}, Start time is ${START_TIME},and preloading time is ${PRELOADING_TIME_MS}`);
    return Date.now() - START_TIME > PRELOADING_TIME_MS ? true : false;
}, _PreLoader_isHaveFirebaseApp = function _PreLoader_isHaveFirebaseApp(FIREBASE_APP) {
    return FIREBASE_APP ? true : false;
}, _PreLoader_sendStartSignalToFirebase = function _PreLoader_sendStartSignalToFirebase(FIREBASE_APP) {
    FIREBASE_APP.uploadData(`PreLoader/status`, "preparing");
}, _PreLoader_startAutoCloseBroadcastMonitor = function _PreLoader_startAutoCloseBroadcastMonitor(FIREBASE_APP) {
    const timerId = setInterval(() => __awaiter(this, void 0, void 0, function* () {
        const CAN_BE_CLOSED = yield __classPrivateFieldGet(this, _PreLoader_instances, "m", _PreLoader_isReadyToCloseBroadcastPreloader).call(this, FIREBASE_APP);
        if (CAN_BE_CLOSED) {
            clearInterval(timerId);
            yield this.closePreLoader("BroadcastMonitoringMode");
        }
    }), 500);
}, _PreLoader_isReadyToCloseBroadcastPreloader = function _PreLoader_isReadyToCloseBroadcastPreloader(FIREBASE_APP) {
    return __awaiter(this, void 0, void 0, function* () {
        const STATUS = yield FIREBASE_APP.downloadData(`PreLoader/status`);
        return STATUS === "readyToClose" ? true : false;
    });
};
class App {
    constructor() {
        this.init();
    }
    init() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.loadGeoData();
            yield this.initAfterAndGetCurrentPosition();
        });
    }
    loadGeoData() {
        return __awaiter(this, void 0, void 0, function* () {
            const RESPONSE = yield fetch("turuoka.json");
            this.GEO_DATA = yield RESPONSE.json();
        });
    }
    initAfterAndGetCurrentPosition() {
        return __awaiter(this, void 0, void 0, function* () {
            navigator.geolocation.getCurrentPosition((position) => __awaiter(this, void 0, void 0, function* () {
                const { longitude, latitude } = position.coords;
                this.CURRENT_POINT = turf.point([longitude, latitude]);
                alert(`Longitude : ${this.CURRENT_POINT.geometry.coordinates[0]},latitude : ${this.CURRENT_POINT.geometry.coordinates[1]}`);
            }));
        });
    }
}
const APP = new App();
//# sourceMappingURL=map.js.map