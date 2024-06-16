# 通过 bpftime 已有代码来动态应用 zpoline 来劫持改变 write 系统调用行为
## zpoline 部分
代码 zpoline 子文件夹，见 https://github.com/yasukata/zpoline 里对代码的解释。
我把 __zpoline_init 函数名改成了 bpftime_agent_main，方便 bpftime cli 识别，不用修改很多 bpftime cli 的代码逻辑。
在运行准备被监控的进程，比如 example/writev_test 时，需要设置 LIBZPHOOK 环境变量为 hook_func_def 里编译出来的 so 库的绝对路径。

## bpftime 部分
我只用了 bpftime 的 cli 部分使用 frida 动态注入 so 库的代码。

## 运行

```
sudo make release JOBS=$(nproc) //编译安装 bpftime cli 到 /root/.bpftime
make -C zpoline
make -C zpoline/hook_func_def
sudo cp zpoline/libzpoline /root/.bpftime 

// 另一个终端
export LIBZPHOOK=./zpoline/hook_func_def/libzphook_basic.so
./example/writev_test/<executable file>

// 另一个终端
sudo /root/.bpftime/bpftime intercept <pid of target process>
```
    