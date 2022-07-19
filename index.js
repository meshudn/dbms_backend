const express = require("express");
const fetch = require("axios");
var bodyParser = require('body-parser');
var cors = require('cors');
const FormData = require('form-data');
const multer  = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);
const bcrypt = require('bcrypt');
const saltRounds = 10;
const db = require('./database');
const { isErrored } = require("stream");
var hashFile;

const app = express();

app.use(cors());
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.use(express.json());




const multerStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "uploads");
    },
    filename: (req, file, cb) => {
      const ext = file.mimetype.split("/")[1];
      file.originalname = file.originalname.split(" ").join("");
      cb(null, `${file.originalname.split(".")[0]}-${Date.now()}.${ext}`);
    },
  });

//Calling the "multer" Function
const upload = multer({
    storage: multerStorage
  });


//making db query async..
const query = promisify(db.query).bind(db);




// login process using selenium webdriver


let app_cookie = '_e28a0539dd247279abd0fb209bed8166';
let WTC_AUTHENTICATED = "nmes";

let swd = require("selenium-webdriver");
let driver = require("chromedriver");

let browser = new swd.Builder();
let tab = browser.forBrowser("chrome").build();

let username1 = "nmes";
let password = "Ihatefaking1";

let tabToOpen =
tab.get("https://wtc.tu-chemnitz.de/krb/module.php/negotiate/backend.php?AuthState=_72a88110a5e5120082417a9156a39a41741d3cb1ac%3Ahttps%3A%2F%2Fwtc.tu-chemnitz.de%2Fkrb%2Fsaml2%2Fidp%2FSSOService.php%3Fspentityid%3Dhttps%253A%252F%252Fwww.tu-chemnitz.de%252Fshibboleth%26RelayState%3Dss%253Amem%253A5d1c683939ce75f7825269c40bf29717138a2721e6cb5e0bbb4fd8454fc13ee9%26cookieTime%3D1657164631");
tabToOpen
.then(function () {

    // Timeout to wait if connection is slow
    let findTimeOutP =
        tab.manage().setTimeouts({
            implicit: 10000, // 10 seconds
        });
    return findTimeOutP;
})

.then(function () {

    // Step 2 - Finding the username input
    let promiseUsernameBox =
        tab.findElement(swd.By.css("#username"));
    return promiseUsernameBox;
})
.then(function () {

    // Step 2 - Finding the username input
    let promiseUsernameBox =
        tab.findElement(swd.By.css("#username"));
    return promiseUsernameBox;
})
.then(function (usernameBox) {

    // Step 3 - Entering the username
    let promiseFillUsername =
        usernameBox.sendKeys(username1);
    return promiseFillUsername;
})
.then(function () {

    // Step 6 - Finding the Sign In button
    let promiseSignInBtn = tab.findElement(
        swd.By.css(".btn.btn-default")
    );
    return promiseSignInBtn;
})
.then(function (signInBtn) {

    // Step 7 - Clicking the Sign In button
    let promiseClickSignIn = signInBtn.click();
    return promiseClickSignIn;
})
.then(function () {
    console.log(
        "Username entered successfully in"
    );

    // Step 4 - Finding the password input
    let promisePasswordBox =
        tab.findElement(swd.By.css("#password"));
    return promisePasswordBox;
})
.then(function (passwordBox) {

    // Step 5 - Entering the password
    let promiseFillPassword =
        passwordBox.sendKeys(password);
    return promiseFillPassword;
})
.then(function () {

    // Step 6 - Finding the Sign In button
    let promiseSignInBtn = tab.findElement(
        swd.By.css(".btn.btn-default")
    );
    return promiseSignInBtn;
})
.then(function (signInBtn) {

    // Step 7 - Clicking the Sign In button
    let promiseClickSignIn = signInBtn.click();
    return promiseClickSignIn;
})
.then(function () {
    console.log("Connected with Webservice!");

    tab.manage().getCookie('_shibsession_7777772e74752d6368656d6e69747a2e64655f61707068747470733a2f2f7777772e74752d6368656d6e69747a2e64652f73686962626f6c657468').then(function (cookie) {
        console.log('cookie details => ', cookie);
        app_cookie = cookie.value;

        tab.close();
      });
})
.catch(function (err) {
    console.log("Error ", err, " occurred!");
    tab.close();
});







// check file hash into the web service

async function checkFileHash(filehash){
    const opts = {
        method: 'GET',
        headers: {
            cookie: 'WTC_AUTHENTICATED=nmes; _shibsession_7777772e74752d6368656d6e69747a2e64655f61707068747470733a2f2f7777772e74752d6368656d6e69747a2e64652f73686962626f6c657468='+app_cookie
        },
    };

    let status = "";
    const putHash = await fetch(`https://www.tu-chemnitz.de/informatik/DVS/blocklist/`+ filehash, opts);

    console.log("webservice response: " + putHash.status);
    return putHash.status;
}


// code started from here.
// Route: /uploads

app.post("/uploads", upload.single("file"), async (req, res)=>{
    //console.log(req.file);
    
    const fileBuffer = await fs.readFileSync(req.file.path);
    const hashSum = crypto.createHash('sha256');
    hashSum.update(fileBuffer);

    hashFile = hashSum.digest('hex');

    console.log(hashFile);

    const result = await checkFileHash(hashFile);

    let status;
    if(result === 210){
        status = 0;
    }
    if(result === 200){
        status = 1;
    }

    const url = "db" + crypto.randomUUID();

    const date = new Date();

    const user_id = req.body.user_id;


    const queryString = "INSERT INTO uploads (filename, content, type, size, download_url, create_date, filehash, user_id, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)";   

    try{
        const insertItem = await query(queryString, [req.file.filename, fileBuffer, req.file.mimetype, req.file.size, url, date, hashFile, user_id, status]);
        if(insertItem.insertId){
            const result = {
                url: url
            }
            // download link send to the user.
            res.status(200).send(JSON.stringify(result));
        }
    }catch(e){
        console.log("error: insert failed " + e);
        res.status(500);
    }
     //file deleted
     await unlinkAsync(req.file.path);
});

app.put("/uploads", async (req, res)=>{
    //console.log(req.body);

    const download_url = req.body.download_url;
    let fileHash;
    const action = req.body.action;

    //updating webservice
    
    //getting the hash from the database
    const getHashQuery = "SELECT * from uploads WHERE download_url = ?";   

    try{
        const insertItem = await query(getHashQuery, [download_url]);
        if(insertItem){
            console.log("filehash: " + insertItem[0].filehash);
            fileHash = insertItem[0].filehash;
        }else{
            res.status(404).send(JSON.stringify(""));
        }
    }catch(e){
        console.log("error: insert failed " + e);
        res.status(500).send(JSON.stringify(""));
    }


    if(action){
        if(action == "block"){
            const opts = {
                method: 'PUT',
                headers: {
                    cookie: 'WTC_AUTHENTICATED=nmes; _shibsession_7777772e74752d6368656d6e69747a2e64655f61707068747470733a2f2f7777772e74752d6368656d6e69747a2e64652f73686962626f6c657468='+app_cookie
                },
            };
        
            let status = "";
            const putHash = await fetch(`https://www.tu-chemnitz.de/informatik/DVS/blocklist/`+ fileHash, opts);
        
            console.log("webservice: " + putHash.status);
            if(putHash.status === 201){
                console.log("filehash put:" +putHash.status);
                  // updating db.
                queryString = "UPDATE uploads SET active = 0 WHERE download_url = ?";   
                try{
                    const insertItem = await query(queryString, [download_url]);
                    if(insertItem){
                        res.status(200).send(JSON.stringify(insertItem));
                    }else{
                        res.status(404).send(JSON.stringify(""));
                    }
                }catch(e){
                    console.log("error: update failed " + e);
                    res.status(500).send(JSON.stringify(""));
                }
            }else{
                res.status(400).send();
            }
        }
        if(action == "unblock"){
            const opts = {
                method: 'DELETE',
                headers: {
                    cookie: 'WTC_AUTHENTICATED=nmes; _shibsession_7777772e74752d6368656d6e69747a2e64655f61707068747470733a2f2f7777772e74752d6368656d6e69747a2e64652f73686962626f6c657468='+app_cookie
                },
            };
        
            let status = "";
            const putHash = await fetch(`https://www.tu-chemnitz.de/informatik/DVS/blocklist/`+ fileHash, opts);
        
            if(putHash.status === 204){
                console.log("filehash put:" +putHash.status);
                  // updating db.
                queryString = "UPDATE uploads SET active = 1 WHERE download_url = ?";   
                try{
                    const insertItem = await query(queryString, [download_url]);
                    if(insertItem){
                        res.status(200).send(JSON.stringify(insertItem));
                    }else{
                        res.status(404).send(JSON.stringify(""));
                    }
                }catch(e){
                    console.log("error: update failed " + e);
                    res.status(500).send(JSON.stringify(""));
                }
            }else{
                res.status(400).send();
            }
        }
    }
    
});

app.get("/uploads/:id", async (req, res)=>{
    //console.log(req.file);
    
    const username = req.params.id;

    const queryString = "SELECT * from uploads WHERE user_id = ?";   

    try{
        const insertItem = await query(queryString, [username]);
        if(insertItem){
            // download link send to the user.
            res.status(200).send(JSON.stringify(insertItem));
        }else{
            res.status(404).send(JSON.stringify(""));
        }
    }catch(e){
        console.log("error: insert failed " + e);
        res.status(500).send(JSON.stringify(""));
    }

});

app.delete("/uploads/:id", async (req, res)=>{
    const id = req.params.id;
    console.log("requests delete:" + id);

    queryStringRequest = "DELETE FROM uploads WHERE id = ?"; 

    try{
         const insertItem = await query(queryStringRequest, [id]);
        if(insertItem){
            // download link send to the user.
             console.log("uploads table deleted");
            console.log(insertItem);
            res.status(200).send(JSON.stringify(insertItem));
        }else{
             res.status(404).send(JSON.stringify(""));
        }
    }catch(e){
        console.log("error: update failed " + e);
        res.status(500).send(JSON.stringify(""));
        }
 });

app.get("/download/:id", async (req, res)=>{
    //console.log(req.file);
    
    const download_url = req.params.id;

    const queryString = "SELECT * from uploads WHERE download_url = ?";   

    try{
        const insertItem = await query(queryString, [download_url]);
        if(insertItem){
            // download link send to the user.
            res.status(200).send(JSON.stringify(insertItem));
        }else{
            res.status(404).send(JSON.stringify(""));
        }
    }catch(e){
        console.log("error: insert failed " + e);
        res.status(500).send(JSON.stringify(""));
    }

});

app.post("/user-register/", async (req, res)=>{
    console.log(req.body);

    const username = req.body.username;
    const pass = req.body.password;

    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(pass, salt);

    const queryString = "INSERT INTO users (username,password) VALUES (?, ?)";   

    
        try{
            const insertItem = await query(queryString, [username,password]);
            if(insertItem){
                // download link send to the user.
                console.log(insertItem);
                res.status(200).send(JSON.stringify(insertItem));
            }else{
                res.status(404).send(JSON.stringify(""));
            }
        }catch(e){
            console.log("error: update failed " + e);
            res.status(500).send(JSON.stringify(""));
        }
});

let user;
app.put("/user-login/", async (req, res)=>{
    console.log(req.body);

    const username = req.body.username;
    const pass = req.body.password;

    let passwordMatch;

    const queryString = "SELECT * from users WHERE username = ?";   
   
        try{
            user = await query(queryString, [username]);
            if(user){
              console.log(user[0].password);  
              passwordMatch = await bcrypt.compare(pass, user[0].password);

              console.log(passwordMatch);
              if(passwordMatch == true){
                const msg = `{username: ${username}}`;
                res.status(200).send(JSON.stringify(msg));
              }else{
                    res.status(404).send("");
               }
            }
        }catch(e){
            console.log("error: no user found " + e);
            res.status(404).send(JSON.stringify(""));
        }
   
});

app.get("/requests", async (req, res)=>{
    const queryString = "SELECT * from requests WHERE approved = 0";  
        try{
            const insertItem = await query(queryString);
            if(insertItem){
                // download link send to the user.
                console.log(insertItem);
                res.status(200).send(JSON.stringify(insertItem));
            }else{
                res.status(404).send(JSON.stringify(""));
            }
        }catch(e){
            console.log("error: update failed " + e);
            res.status(500).send(JSON.stringify(""));
        }
});

let queryString1;
app.post("/requests", async (req, res)=>{

    const action = req.body.action;
    const upload_url = req.body.download_url;
    let user_id = req.body.user_id;
    const upload_id = req.body.upload_id;
    const reasonText = req.body.reason_text;

    if(user_id == ''){
        user_id = "guest";
    }
    let status;
    if(action == "block"){
        status = 1;
    }else{
        status = 0
    }

    const queryString1 = "INSERT INTO requests (reason_text, user_id, status, approved, upload_id, upload_url) VALUES (?, ?, ?, ?, ?, ?)";   

        try{
            const insertItem = await query(queryString1, [reasonText, user_id, status, 0, upload_id, upload_url]);
            if(insertItem){
                // download link send to the user.
                console.log(insertItem);
                res.status(200).send(JSON.stringify(insertItem));
            }else{
                res.status(404).send(JSON.stringify(""));
            }
        }catch(e){
            console.log("error: update failed " + e);
            res.status(500).send(JSON.stringify(""));
        }
});

let queryStringRequest;
app.put("/requests/:id", async (req, res)=>{
    const id = req.params.id;

    const action = req.body.action;
    console.log("requests:" + req.body);

    if(action){
        if(action == "block"){
            queryStringRequest = "UPDATE requests SET status = 0, approved = 1 WHERE id = ?";   
        }
        if(action == "unblock"){
            queryStringRequest = "UPDATE requests SET status = 1, approved = 1 WHERE id = ?";   
        }
        
        try{
            const insertItem = await query(queryStringRequest, [id]);
            if(insertItem){
                // download link send to the user.
                console.log("request table updated");
                console.log(insertItem);
                res.status(200).send(JSON.stringify(insertItem));
            }else{
                res.status(404).send(JSON.stringify(""));
            }
        }catch(e){
            console.log("error: update failed " + e);
            res.status(500).send(JSON.stringify(""));
        }
    }
});

app.delete("/requests/:id", async (req, res)=>{
    const id = req.params.id;
    console.log("requests delete:" + id);

    queryStringRequest = "DELETE FROM requests WHERE id = ?"; 

    try{
         const insertItem = await query(queryStringRequest, [id]);
        if(insertItem){
            // download link send to the user.
             console.log("request table deleted");
            console.log(insertItem);
            res.status(200).send(JSON.stringify(insertItem));
        }else{
             res.status(404).send(JSON.stringify(""));
        }
    }catch(e){
        console.log("error: update failed " + e);
        res.status(500).send(JSON.stringify(""));
        }
 });



//testing purpose only..
app.get("/blocktest", (req, ress)=>{
    console.log("inside blocktest");
    const opts = {
        headers: {
            cookie: 'WTC_AUTHENTICATED=nmes; _shibsession_7777772e74752d6368656d6e69747a2e64655f61707068747470733a2f2f7777772e74752d6368656d6e69747a2e64652f73686962626f6c657468='+app_cookie
        }
    };
    const fileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    fetch(`https://www.tu-chemnitz.de/informatik/DVS/blocklist/`+ fileHash, opts)
    .then(res => {
        console.log(res);
        if(res.status == 404){
            ress.status(404).send("");
        }else if(res.status == 210){
            ress.status(210).send("blocked");
        }
        else if (res.status == 200){
            ress.status(200).send("ok");
        }
    })
    .catch(err => console.log(err));
});

app.listen(3030);