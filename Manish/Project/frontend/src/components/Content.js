import React, { useState } from "react";
import axios from "axios";
import { useSelector } from "react-redux";

const Content = () => {
  const { user } = useSelector((store) => store.user);
  const [output, setOutput] = useState("");

  const runScript = async (script) => {
    try {
      const res = await axios.post("http://localhost:5000/run-script", { script });
      setOutput(res.data.output);
    } catch (err) {
      setOutput(err.response?.data?.error || err.message);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-bold mb-4">Welcome, {user?.username}!</h1>

      <div className="grid grid-cols-2 gap-4">
        <button
          className="p-2 bg-blue-500 text-white rounded"
          onClick={() => runScript("restart1")}
        >
          Restart Server 1
        </button>
        <button
          className="p-2 bg-blue-500 text-white rounded"
          onClick={() => runScript("restart2")}
        >
          Restart Server 2
        </button>
        <button
          className="p-2 bg-green-500 text-white rounded"
          onClick={() => runScript("update1")}
        >
          Update Server 1
        </button>
        <button
          className="p-2 bg-green-500 text-white rounded"
          onClick={() => runScript("update2")}
        >
          Update Server 2
        </button>
      </div>

      {output && (
        <pre className="mt-4 p-2 border rounded bg-gray-100">{output}</pre>
      )}
    </div>
  );
};

export default Content;

