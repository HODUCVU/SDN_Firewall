function edit_council(councilId) {
  // Gửi yêu cầu GET để lấy dữ liệu thông báo hiện tại
  axios
    .get(`/api/v1/councils/${councilId}`)
    .then((response) => {
      const councilData = response.data.data;
      // Hiển thị modal chỉnh sửa và điền dữ liệu vào biểu mẫu
      showEditForm(councilData);
    })
    .catch((error) => {
      console.error("Error fetching council data:", error);
    });
}

function showEditForm(councilData) {
  const TenHoiDong = document.getElementById(`editName-${councilData._id}`);
  const ChuTich = document.getElementById(
    `userDropdown-editChuTich-${councilData._id}`
  );
  const ThuKy = document.getElementById(
    `userDropdown-editThuKy-${councilData._id}`
  );
  const UyVien1 = document.getElementById(
    `userDropdown-editUyVien1-${councilData._id}`
  );
  const UyVien2 = document.getElementById(
    `userDropdown-editUyVien2-${councilData._id}`
  );

  if (!councilData.UyVien2) {
    councilData.UyVien2 = "";
  }
  if (!councilData.UyVien1) {
    councilData.UyVien1 = "";
  }

  TenHoiDong.value = councilData.TenHoiDong;
  ChuTich.value = councilData.ChuTich;
  ThuKy.value = councilData.ThuKy;
  UyVien1.value = councilData.UyVien1;
  UyVien2.value = councilData.UyVien2;
  const editNotify = document.getElementById(`council-${councilData._id}`);
  editNotify.style.display = "block";
}

// Hàm đóng modal chỉnh sửa
function closeEditCouncil(councilId) {
  const editNotify = document.getElementById(`council-${councilId}`);
  editNotify.style.display = "none";
  location.reload();
}

// Hàm lưu thông báo chỉnh sửa
function saveEditCouncil(councilId) {
  const TenHoiDong = document.getElementById(`editName-${councilId}`);
  const ChuTich = document.getElementById(
    `userDropdown-editChuTich-${councilId}`
  );
  const ThuKy = document.getElementById(`userDropdown-editThuKy-${councilId}`);
  const UyVien1 = document.getElementById(
    `userDropdown-editUyVien1-${councilId}`
  );
  const UyVien2 = document.getElementById(
    `userDropdown-editUyVien2-${councilId}`
  );
  const editedData = {
    TenHoiDong: TenHoiDong.value,
    ChuTich: ChuTich.value,
    ThuKy: ThuKy.value,
    UyVien1: UyVien1.value,
    UyVien2: UyVien2.value,
  };

  // Gửi yêu cầu PUT/PATCH để cập nhật thông báo
  axios
    .patch(`/api/v1/councils/${councilId}`, editedData)
    .then((response) => {
      closeEditCouncil(councilId);
    })
    .catch((error) => {
      console.error("Error updating council:", error);
    });
}
