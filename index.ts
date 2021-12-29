import { SignedRequest } from './SignedRequest';
import express from 'express';
import bodyParser from 'body-parser';

const app = express();

// use body-parser middlewares
app.use(bodyParser.text());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.post('/signed-request', async (req, res) => {
    const payload = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const signedRequest = new SignedRequest(payload);

    res.send(await signedRequest.send());
});

// Make Express listens on port 3000
app.listen(3000, () => {
    console.log('Listening on port 3000');
}
);
