const express = require('express');
const router = express.Router();
const products = require('../controllers/products');
const multer = require('multer');
const {checkRole} = require('../middleware/auth');
const verifyRole = require('../middleware/verifyToken');

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
router.get('/view', verifyRole, products.getProducts);
router.post('/store', verifyRole, checkRole(['admin']), imageUpload.single('images'), products.storeProduct);
router.delete('/remove/:id', verifyRole, checkRole(['admin']), products.deleteProduct);
router.put('/edit/:id', verifyRole, checkRole(['admin']), products.updateProduct);


module.exports = router;