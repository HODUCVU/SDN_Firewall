// Khi người dùng chọn thêm council
function new_council() {
  // Hiển thị modal chỉnh sửa
  const editcouncil = document.getElementById(`newcouncil`);
  editcouncil.style.display = "block";
}

// Hàm đóng modal chỉnh sửa
function closeNewcouncil() {
  const editcouncil = document.getElementById(`newcouncil`);
  editcouncil.style.display = "none";
  location.reload();
}

// Hàm lưu thông báo chỉnh sửa
function saveNewcouncil() {
  const TenHoiDong = document.getElementById(`TenHoiDong`);
  const ChuTich = document.getElementById("userDropdown-ChuTich");
  const ThuKy = document.getElementById("userDropdown-ThuKy");
  const UyVien1 = document.getElementById("userDropdown-UyVien1");
  const UyVien2 = document.getElementById("userDropdown-UyVien2");
  const Data = {
    TenHoiDong: TenHoiDong.value,
    ChuTich: ChuTich.value,
    Thuky: ThuKy.value,
  };
  if (UyVien2.value) {
    Data.UyVien2 = UyVien2.value;
  }
  if (UyVien1.value) {
    Data.UyVien1 = UyVien1.value;
  }
  // Gửi yêu cầu PUT/PATCH để cập nhật thông báo
  axios
    .post(`/api/v1/councils`, Data)
    .then((response) => {
      console.log("create council successfully", response.data);

      // Đóng modal và có thể cập nhật lại giao diện hoặc tải lại trang
      closeNewcouncil();
    })
    .catch((error) => {
      console.error("Error updating council:", error);
    });
}
