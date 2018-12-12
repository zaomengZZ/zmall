package com.mmall.service.impl;

import com.mmall.common.Const;
import com.mmall.common.ServerResponse;
import com.mmall.common.TokenCache;
import com.mmall.dao.UserMapper;
import com.mmall.pojo.User;
import com.mmall.service.IUserService;
import com.mmall.util.MD5Util;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.UUID;

@Service("iUserService")
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;
    @Override
    public ServerResponse<User> login(String username, String password) {
        int resultcount = userMapper.checkUsername(username);
        if(resultcount==0){
            return ServerResponse.createByErrorMessage("用户名不存在");
        }
        String md5Password=MD5Util.MD5EncodeUtf8(password);

        User user=userMapper.selectLogin(username,md5Password);
        if(user==null){
            return  ServerResponse.createByErrorMessage("密码错误");
        }
        user.setPassword(StringUtils.EMPTY);
        return ServerResponse.createBySuccessMessage("登录成功",user);
    }

    @Override
    public ServerResponse<String> register(User user){
        ServerResponse validResponse = this.checkValid(user.getUsername(),Const.USERNAME);
        if(!validResponse.isSuccess()){
            return validResponse;
        }
        validResponse = this.checkValid(user.getEmail(),Const.EMAIL);
        if(!validResponse.isSuccess()){
            return validResponse;
        }
        user.setRole(Const.Role.ROLE_CUSTOMER);
        //MD5加密
        user.setPassword(MD5Util.MD5EncodeUtf8(user.getPassword()));
        int resultCount = userMapper.insert(user);
        if(resultCount == 0){
            return ServerResponse.createByErrorMessage("注册失败");
        }
        return ServerResponse.createBySuccessMessage("注册成功");
    }

    public ServerResponse<String> checkValid(String str,String type){
        if(org.apache.commons.lang3.StringUtils.isNotBlank(type)){
            //开始校验
            if(Const.USERNAME.equals(type)){
                int resultCount = userMapper.checkUsername(str);
                if(resultCount > 0 ){
                    return ServerResponse.createByErrorMessage("用户名已存在");
                }
            }
            if(Const.EMAIL.equals(type)){
                int resultCount = userMapper.checkEmail(str);
                if(resultCount > 0 ){
                    return ServerResponse.createByErrorMessage("email已存在");
                }
            }
        }else{
            return ServerResponse.createByErrorMessage("参数错误");
        }
        return ServerResponse.createBySuccessMessage("校验成功");
    }

    @Override
    public  ServerResponse selectQuestion(String username){
        ServerResponse validResponse=this.checkValid(username,Const.USERNAME);

        if(validResponse.isSuccess()){
            //用户不存在
            return ServerResponse.createByErrorMessage("用户不存在");

        }
        String question =userMapper.selectQuestionByUsername(username);

        if(StringUtils.isNotBlank(question)){
            return ServerResponse.createBySuccess(question);
        }
        return ServerResponse.createByErrorMessage("找回密码门的问题是空");

    }

    public ServerResponse<String> CheckAnswer(String username,String question,String answer){
        int resultCount=userMapper.checkAnwser(username,question,answer);

        if(resultCount>0){
            //说明问题及问题答案是这个用户的,并且回答正确

            String forgetToken= UUID.randomUUID().toString();

            TokenCache.setKey(TokenCache.TOKEN_PREFIX+username,forgetToken);

            return ServerResponse.createBySuccess(forgetToken);

        }
        //说明问题是这个用户，但是回答错误
        return  ServerResponse.createByErrorMessage("回答错误");
    }

    public ServerResponse<String> resetPassword(String passwordOld,String passwordNew,User user) {
        //防止横向越权，要校验一下这个用户的旧密码，一定要指向这个用户。因为我们会查询一个count(1),如果不指定id,那么结果可能就是true  count>0
        int resultCount = userMapper.checkPassword(MD5Util.MD5EncodeUtf8(passwordOld), user.getId());
        if (resultCount == 0) {
            return ServerResponse.createByErrorMessage("旧密码错误，修改失败");
        }
        user.setPassword(MD5Util.MD5EncodeUtf8(passwordNew));

        int updateCount = userMapper.updateByPrimaryKeySelective(user);

        if (updateCount > 0) {
            return ServerResponse.createBySuccessMessage("修改成功");
        }
        return ServerResponse.createByErrorMessage("密码更新失败");
    }

    public  ServerResponse<User> updateInformation(User user){

        //username是不能被更新的
        //email也要进行校验，校验新的email是不是已经存在，如果当存在相同的email的话，不能是我们当前的用户的

        int resuletCount=userMapper.checkEmailByUserId(user.getEmail(),user.getId());


        if(resuletCount>0){
            return ServerResponse.createByErrorMessage("邮箱已被使用,请更换后重试");
        }
        User updateUser=new User();
        updateUser.setId(user.getId());
        updateUser.setEmail(user.getEmail());
        updateUser.setPhone(user.getPhone());
        updateUser.setQuestion(user.getQuestion());
        updateUser.setAnswer(user.getAnswer());

        int updateCount=userMapper.updateByPrimaryKeySelective(updateUser);

        if(updateCount>0){
            return  ServerResponse.createBySuccess();
        }
        return ServerResponse.createByErrorMessage("更新个人信息失败,请稍后重试");

    }

    public ServerResponse<User> getInformation(Integer userId){
        User user= userMapper.selectByPrimaryKey(userId);
        if(user==null){
            ServerResponse.createByErrorMessage("找不到当前用户");
        }
        //将返回给Controlller层的密码设置为空，不传给前台
        user.setPassword(StringUtils.EMPTY);
        return  ServerResponse.createBySuccess(user);
    }

}
