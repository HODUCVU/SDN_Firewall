// new_user.js
import { showAlert, hideAlert } from "./showAlert";

const newUser = async (id, password, name, role) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/api/v1/users/signup",
      data: {
        id,
        password,
        name,
        role,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "Signup successful!");
      window.setTimeout(() => {
        location.assign("/users");
      }, 1500);
    }
  } catch (err) {
    console.log(err.response.data.data);
    showAlert("error", err.response.data.error);
  }
};

const userForm = document.querySelector(".new-user");
userForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = document.getElementById("id").value;
  const password = document.getElementById("password").value;
  const name = document.getElementById("name").value;
  const role = document.getElementById("role").value;
  await newUser(id, password, name, role);
});
