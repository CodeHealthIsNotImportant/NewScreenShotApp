// backend/server.js
import express from "express";
import cors from "cors";
import { exec } from "child_process";

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

// Map button actions to scripts
const scripts = {
  restart1: "node scrp_rs1.js",
  restart2: "node scrp_rs2.js",
  update1: "node scrp_up1.js",
  update2: "node scrp_up2.js",
};

app.post("/run-script", (req, res) => {
  const { script } = req.body;

  if (!scripts[script]) {
    return res.status(400).json({ error: "Invalid script name" });
  }

  exec(scripts[script], (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: error.message });
    if (stderr) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});

