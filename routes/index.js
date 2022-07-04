var express = require('express');
var router = express.Router();
const multer = require('multer');
require('dotenv').config()
const axios = require('axios');
let fs = require('fs');
let FormData = require('form-data');

const storage = multer.diskStorage({
    destination: './files',
    filename: (req, file, cb) => {
        return cb(null, `${file.originalname}`);
    },
});

const upload = multer({
    storage: storage,
});

router.get('/', function (req, res, next) {
    res.render('index', {title: 'Express'});
});

router.post('/upload', upload.single('file'), function (req, res, nex) {
    let form = FormData();
    form.append("file", fs.createReadStream(`files/${req.file.filename}`));

    axios
        .post(`https://www.virustotal.com/api/v3/files`, form, {
            headers: {
                "x-apikey": process.env.NODE_APP_VIRUS_TOTAL_API,
                "Content-Type": "multipart/form-data"
            }
        })
        .then(result => {
            res.send(result.data.data);
        })
        .catch(error => {
            res.send(error.data.data);
        });
});

router.post('/file/analyse', function (req, res, next) {
    var id = req.body.file_id;
    axios
        .get(`https://www.virustotal.com/api/v3/analyses/${id}`, {
            headers: {
                "x-apikey": process.env.NODE_APP_VIRUS_TOTAL_API,
            }
        })
        .then(result => {
            res.send(result.data.data);
        })
        .catch(error => {
            res.send(error.data.data);
        });
})

router.post('/url', function (req, res, next) {
    var url = req.body.url;
    axios
        .get(`https://www.virustotal.com/api/v3/domains/${url}`, {
            headers: {
                "x-apikey": process.env.NODE_APP_VIRUS_TOTAL_API,
            }
        })
        .then(result => {
            res.send(result.data.data);
        })
        .catch(error => {
            res.send(error.data.data);
        });
});

module.exports = router;
