const { exec } = require("child_process");

// Change this command to whatever you want to execute
const command = "ansible-playbook -i inventory_new.yaml update2.yaml";

exec(command, (error, stdout, stderr) => {
  if (error) {
    console.error("Error:", error.message);
    return;
  }
  if (stderr) {
    console.error("stderr:", stderr);
    return;
  }
  console.log("OUTPUT:\n" + stdout);
});