#include <signal.h>
#include <iostream>
#include "Network/UdpServer.h"
#include "Poller/EventPoller.h"
#include "SrtSession.hpp"

using namespace SRT;
using namespace toolkit;
using namespace std;

int main(int argc,char *argv[]) {
    //设置日志
    Logger::Instance().add(std::make_shared<ConsoleChannel>());

     auto rtcSrv = std::make_shared<UdpServer>();
        rtcSrv->setOnCreateSocket([](const EventPoller::Ptr &poller, const Buffer::Ptr &buf, struct sockaddr *, int) {
            if (!buf) {
                return Socket::createSocket(poller, false);
            }
            auto new_poller = SrtSession::queryPoller(buf);
            if (!new_poller) {
                //该数据对应的srt对象未找到，丢弃之
                return Socket::Ptr();
            }
            return Socket::createSocket(new_poller, false);
        });

          try {
            //srt udp服务器
            rtcSrv->start<SrtSession>(8080);

        } catch (std::exception &ex) {
            WarnL << "端口占用或无权限:" << ex.what() << endl;
            ErrorL << "程序启动失败，请修改配置文件中端口号后重试!" << endl;
            sleep(1);
            return -1;
        }

              //设置退出信号处理函数
        static semaphore sem;
        signal(SIGINT, [](int) {
            InfoL << "SIGINT:exit";
            signal(SIGINT, SIG_IGN);// 设置退出信号
            sem.post();
        });// 设置退出信号
        sem.wait();


}