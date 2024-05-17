import axios from "axios";

exports.sendMessage = async (formData) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/api/v1/messages",
      data: formData,
    });
    console.log([...formData]);
    if (res.data.status === "success") {
      console.log("ó");
    }
  } catch (err) {
    console.log("error", err);
  }
};
