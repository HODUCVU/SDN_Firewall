const sqlite3 = require('sqlite3').verbose();

const http = require('http');
const request = require('request');
const root_url = "http://127.0.0.1:8080"

exports.home = async (req, res, next) => {
    let db = new sqlite3.Database('../../SDN_Firewall/Firewall/dataset/firewall-drop.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Connected to the firewall database.');
  });
    db.serialize(() => {
        db.all(`SELECT src_ip, dst_ip, protocol, src_port, dst_port, state, action FROM firewall_rules`, (err, row) => {
          if (err) {
            console.error(err.message);
          }
          res.status(200).render("home", { row });
        });
      });
      
    }
exports.rules = async (req, res, next) => {
      let db = new sqlite3.Database('../../SDN_Firewall/Firewall/dataset/firewall-vTest.db', sqlite3.OPEN_READWRITE, (err) => {
      if (err) {
        console.error(err.message);
      }
      console.log('Connected to the firewall database.');
    });
      db.serialize(() => {
          db.all(`SELECT src_ip, dst_ip, protocol, src_port, dst_port, state, action FROM firewall_rules`, (err, row) => {
            if (err) {
              console.error(err.message);
            }
            res.status(200).render("rule", { row });
          });
        });
        
      }
exports.switch = async (req, res, next) => {
  request(root_url+"/firewall/module/status", (error, response, body) => {
    if (error) {
      console.error('Lỗi khi gọi API:', error);
    } else {
      const data = JSON.parse(body);
      res.status(200).render("switch",{data});
    }
  
  });        
  }
exports.flow = async (req, res, next) => {
    let data ={}
    let summary = {}
    let flowss = {}
    request(root_url+`/data?flowsumm=${req.params.id}`, (error, response, body) => {
      if (error) {
        console.error('Lỗi khi gọi API:', error);
      } else {
        
        summary = JSON.parse(body);
      }
    })
    
    request(root_url+`/data?portdesc=${req.params.id}`, (error, response, body) => {
      if (error) {
        console.error('Lỗi khi gọi API:', error);
      } else {
        data = JSON.parse(body);
        request(root_url+`/data?list=switches`, (error, response, body) => {
          if (error) {
            console.error('Lỗi khi gọi API:', error);
          } else {
            const switches = JSON.parse(body);
            request(root_url+`/status?status=flows&dpid=${req.params.id}`, (error, response, body) => {
              if (error) {
                console.error('Lỗi khi gọi API:', error);
              } else {
                console.log(body)
                flowss = JSON.parse(body);
                res.status(200).render("flow",{data, switches, flowss,summary});

              }
            })
          }
        
        })
      }
    
    });
    
   }
exports.addRule = async (req, res, next) => {
    // Import SQLite library
    const sqlite3 = require('sqlite3').verbose();
    
    // Kết nối đến cơ sở dữ liệu
    let db = new sqlite3.Database('../../SDN_Firewall/Firewall/dataset/firewall-drop.db', sqlite3.OPEN_READWRITE, (err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Connected to the firewall database.');
    });

    // Lấy dữ liệu từ req.body hoặc req.params
    const { src_ip, dst_ip, protocol, src_port, dst_port, state, action } = req.body;
    console.log(req.body)
    // Thực hiện truy vấn INSERT để thêm dữ liệu mới vào cơ sở dữ liệu
    db.run(`INSERT INTO firewall_rules (src_ip, dst_ip, protocol, src_port, dst_port, state, action) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`, [src_ip, dst_ip, protocol, src_port, dst_port, state, action], (err) => {
        if (err) {
            console.error(err.message);
            res.status(500).json({ error: 'Failed to add rule' });
        } else {
            console.log('Rule added successfully');
            res.status(200).json({ status: 'success' });
        }
    });

    // Đóng kết nối cơ sở dữ liệu
    db.close();
}

