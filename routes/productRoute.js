const express = require('express');
const router = express.Router();
const products = require('../controllers/products');
const multer = require('multer');


const imageUpload = multer({

    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, './images/products');
        },
        filename: function (req, file, cb) {
            cb(null, Date.now() + file.originalname);
        }
    }),
});


// Define the login route
router.get('/view', products.getProducts);
router.post('/store', imageUpload.single('images'), products.storeProduct);
router.delete('/remove/:id', products.deleteProduct);
router.put('/edit/:id', products.updateProduct);


module.exports = router;