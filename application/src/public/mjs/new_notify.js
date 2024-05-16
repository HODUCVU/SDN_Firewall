import axios from "axios";
import { showAlert } from "./alerts.js";

export const new_notify = async (ThongBao, NoiDung) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/api/v1/notifys",
      data: {
        ThongBao,
        NoiDung,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "Notify in successfully!");
      window.setTimeout(() => {
        location.assign("/");
      }, 1500);
    }
  } catch (err) {
    console.log(err.response.data.data);
    showAlert("error", err.response.data.error);
  }
};
