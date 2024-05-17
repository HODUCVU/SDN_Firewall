import axios from "axios";
import { showAlert } from "./alerts.js";

export const newtopic = async (formData) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/api/v1/topics",
      data: formData,
    });

    if (res.data.status === "success") {
      showAlert("success", "tạo đề tài thành công!");
      window.setTimeout(() => {
        location.assign("/topics");
      }, 1500);
    }
  } catch (err) {
    console.log(err.response.data.data);
    showAlert("error", err.response.data.error);
  }
};
