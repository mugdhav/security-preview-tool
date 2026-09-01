// Must-detect: CORS open to every origin.
const cors = require("cors");

app.use(cors({ origin: "*" }));
