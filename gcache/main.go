package main

import (
	"fmt"
	"github.com/bluele/gcache"
	"time"
)
// https://mp.weixin.qq.com/s/NnY_0T6pkzOL3hG9kl-ZfA
func main() {
	//fun1()
	fun2()
}
//简单 key/value 设置
func fun1()  {
	gc := gcache.New(20).
		LRU().
		Build()
	gc.Set("key", "ok")
	value, err := gc.Get("key")
	if err != nil {
		panic(err)
	}
	fmt.Println("Get:", value)
}

//设置过期时间
func fun2()  {
	gc:=gcache.New(20).LRU().Build()
	gc.SetWithExpire("key","hhhh",time.Second*10)
	val,_:=gc.Get("key")
	fmt.Println("key",val)

	// Wait for value to expire
	time.Sleep(time.Second*10)

	value, err := gc.Get("key")
	if err != nil {
		panic(err)
	}
	fmt.Println("Get:", value) //panic: Key not found.

}

func fun3(){
	gc := gcache.New(20).
    LRU().
    LoaderFunc(func(key interface{}) (interface{}, error) {
      return "ok", nil
    }).
    Build()
  value, err := gc.Get("key")
  if err != nil {
    panic(err)
  }
  fmt.Println("Get:", value)
}