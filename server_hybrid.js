const https = require("https");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const path = require("path");

const privateKey = fs.readFileSync("private.pem", "utf8");
const publicKey = fs.readFileSync("public.pem", "utf8");
const options = {
    key: fs.readFileSync("server.key"),
    cert: fs.readFileSync("server.cert"),
};

const encrypt = (buffer) => {
    const aesKey = crypto.randomBytes(32); // Genera una clave AES de 256 bits
    const iv = crypto.randomBytes(16); // Genera un vector de inicialización de 128 bits
    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv); // Crea un cifrador AES-256-CBC
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]); // Cifra los datos

    const encryptedKey = crypto.publicEncrypt(publicKey, aesKey); // Cifra la clave AES con la clave pública RSA
    return {
        iv: iv.toString("hex"), // Convierte el IV a hexadecimal
        key: encryptedKey.toString("hex"), // Convierte la clave cifrada a hexadecimal
        data: encrypted.toString("hex"), // Convierte los datos cifrados a hexadecimal
    };
};

const decrypt = (encrypted) => {
    const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(encrypted.key, "hex")); // Descifra la clave AES con la clave privada RSA
    const iv = Buffer.from(encrypted.iv, "hex"); // Convierte el IV de hexadecimal a buffer
    const encryptedData = Buffer.from(encrypted.data, "hex"); // Convierte los datos cifrados de hexadecimal a buffer
    const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv); // Crea un descifrador AES-256-CBC
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]); // Descifra los datos
    return decrypted;
};

const app = express();
const upload = multer({ dest: "uploads/" });

app.post("/encrypt", upload.single("file"), (req, res) => {
    const file = req.file;
    if (!file) {
        res.status(400).send("No file uploaded");
        return;
    }

    fs.readFile(file.path, (err, data) => {
        if (err) {
            res.status(500).send("Error reading file");
            return;
        }

        const encrypted = encrypt(data);
        const encryptedFilePath = path.join(__dirname, "encrypted_files", `${file.originalname}.json`);
        fs.writeFile(encryptedFilePath, JSON.stringify(encrypted), (err) => {
            if (err) {
                res.status(500).send("Error saving encrypted file");
                return;
            }

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ message: "File encrypted and saved", path: encryptedFilePath }));
        });
    });
});

app.post("/decrypt", upload.single("file"), (req, res) => {
    const file = req.file;
    if (!file) {
        res.status(400).send("No file uploaded");
        return;
    }

    fs.readFile(file.path, (err, data) => {
        if (err) {
            res.status(500).send("Error reading file");
            return;
        }

        const encrypted = JSON.parse(data.toString());
        const decrypted = decrypt(encrypted);
        const decryptedFilePath = path.join(__dirname, "decrypted_files", file.originalname.replace(".json", ""));
        fs.writeFile(decryptedFilePath, decrypted, (err) => {
            if (err) {
                res.status(500).send("Error saving decrypted file");
                return;
            }

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ message: "File decrypted and saved", path: decryptedFilePath }));
        });
    });
});

app.get("/", (req, res) => {
    fs.readFile("index_hybrid.html", (err, data) => {
        if (err) {
            res.status(500).send("Error loading HTML page");
            return;
        }
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
    });
});

https.createServer(options, app).listen(8444, () => {
    console.log("Hybrid Server running on https://localhost:8444");
});
