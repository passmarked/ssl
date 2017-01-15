let passmarked = require('../passmarked'),
    ssl = require('./index.js');

passmarked.createRunner(ssl).run({url: 'testagent.cgos.info'})
    .then(info => console.log(info))
    .catch(err => console.log(err.stack));