/* eslint-disable */
import axios from "axios";
import { showAlert } from "./alerts.js";

export const resetPass = async (password) => {
  try {
    const token = window.location.pathname.split("/")[2];
    const res = await axios({
      method: "PATCH",
      url: `/api/v1/users/resetPassword/${token}`,
      data: {
        password,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "Đổi mật khẩu thành công");
    }
  } catch (err) {
    showAlert("error", "Đổi mật khẩu thất bại");
  }
};
