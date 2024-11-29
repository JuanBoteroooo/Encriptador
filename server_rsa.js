const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
app.use(bodyParser.json());

// Leer las claves
const privateKey = fs.readFileSync("private.pem", "utf8");
const publicKey = fs.readFileSync("public.pem", "utf8");

// Ruta para servir el archivo HTML
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Ruta para crear una firma digital
app.post("/sign", (req, res) => {
    const data = req.body.data;

    // Crear un objeto de firma
    const sign = crypto.createSign("SHA256");
    sign.update(data);
    sign.end();

    // Crear la firma digital
    const signature = sign.sign(privateKey, "hex");

    res.json({ signature });
});

// Ruta para verificar una firma digital
app.post("/verify", (req, res) => {
    const data = req.body.data;
    const signature = req.body.signature;

    // Crear un objeto de verificación
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    verify.end();

    // Verificar la firma digital
    const isValid = verify.verify(publicKey, signature, "hex");

    res.json({ isValid });
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
