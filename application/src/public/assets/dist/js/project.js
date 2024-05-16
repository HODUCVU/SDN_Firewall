import { showAlert, hideAlert } from './showAlert';
const newproject=async (Trangthai, NgayThucHien, NgayKetThuc, HoiDong,Thanhvien,MoTa,)=>{
    try{
        const res=await async({
            method: "POST",
            URL: "/api/v1/project/topic",
            data:{
             Trangthai,
             NgayThucHien,
             NgayKetThuc,
             HoiDong,
             Thanhvien,
             MoTa,
          
            }
            
        });
        if (res.data.status === "success") {
            showAlert("success", "project in successfully!");
            window.setTimeout(() => {
              location.assign("new_topic");
            }, 1500);
          }
          
    }catch (err) {
        console.log(err.response.data.data);
        showAlert("error", err.response.data.error);
      }

};
const userForm = document.querySelector(".project");
userForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const Trangthai = document.getElementById("status").value;
  const NgayThucHien = document.getElementById("start_date").value;
  const NgayKetThuc = document.getElementById("end_date").value;
  const HoiDong = document.getElementById("manager").value;
  const Thanhvien = document.getElementById("user").value;
  const MoTa = document.getElementById("desscription").value;
  

  await newproject(Trangthai, NgayThucHien, NgayKetThuc, HoiDong,Thanhvien,MoTa);
});

