// Khi người dùng chọn chỉnh sửa thông báo
function editNotify(notifyId) {
  // Gửi yêu cầu GET để lấy dữ liệu thông báo hiện tại
  axios
    .get(`/api/v1/notifys/${notifyId}`)
    .then((response) => {
      const notifyData = response.data.data;
      // Hiển thị modal chỉnh sửa và điền dữ liệu vào biểu mẫu
      showEditNotifyen(notifyData);
    })
    .catch((error) => {
      console.error("Error fetching notify data:", error);
    });
}

// Hàm hiển thị modal chỉnh sửa và điền dữ liệu vào biểu mẫu
function showEditNotifyen(notifyData) {
  const editThongbaoInput = document.getElementById(
    `editThongbao-${notifyData._id}`
  );
  const editNoidungTextarea = document.getElementById(
    `editNoidung-${notifyData._id}`
  );
  // Điền dữ liệu vào biểu mẫu chỉnh sửa
  editThongbaoInput.value = notifyData.ThongBao;
  editNoidungTextarea.value = notifyData.NoiDung;
  // Hiển thị modal chỉnh sửa
  const editNotify = document.getElementById(`editNotify-${notifyData._id}`);
  editNotify.style.display = "block";
}

// Hàm đóng modal chỉnh sửa
function closeeditNotify(notifyId) {
  const editNotify = document.getElementById(`editNotify-${notifyId}`);
  editNotify.style.display = "none";
  location.reload();
}

// Hàm lưu thông báo chỉnh sửa
function saveEditForm(notifyId) {
  const editThongbaoInput = document.getElementById(`editThongbao-${notifyId}`);
  const editNoidungTextarea = document.getElementById(
    `editNoidung-${notifyId}`
  );

  const editedData = {
    ThongBao: editThongbaoInput.value,
    NoiDung: editNoidungTextarea.value,
  };

  // Gửi yêu cầu PUT/PATCH để cập nhật thông báo
  axios
    .patch(`/api/v1/notifys/${notifyId}`, editedData)
    .then((response) => {
      closeeditNotify(notifyId);
    })
    .catch((error) => {
      console.error("Error updating notify:", error);
    });
}
