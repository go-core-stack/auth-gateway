// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"
	"github.com/go-core-stack/core/utils/smtp"

	"github.com/Prabhjot-Sethi/auth-gateway/api"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/model"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type RegistrationServer struct {
	api.UnimplementedRegistrationServer
	smtpClient *smtp.Client
	validator  *table.EmailVerificationTable
}

func (s *RegistrationServer) initSmtpClient() {
	config := smtp.Config{}

	var ok bool
	config.Host, ok = os.LookupEnv("SMTP_HOST")
	if !ok {
		return
	}

	config.Port, ok = os.LookupEnv("SMTP_PORT")
	if !ok {
		return
	}

	config.Sender, ok = os.LookupEnv("SMTP_SENDER")
	if !ok {
		return
	}

	config.Password, ok = os.LookupEnv("SMTP_PASSWORD")
	if !ok {
		return
	}

	config.SenderName, _ = os.LookupEnv("SMTP_SENDER_NAME")
	config.ReplyTo, _ = os.LookupEnv("SMTP_REPLY_TO")

	s.smtpClient = smtp.New(config)
}

func (s *RegistrationServer) sendMessage(m *smtp.Message) error {
	if s.smtpClient == nil {
		return errors.Wrapf(errors.InvalidArgument, "Smtp Config doesn't exists")
	}

	return s.smtpClient.Send(m)
}

func (s *RegistrationServer) GetRegisterOtp(ctx context.Context, req *api.RegisterOtpReq) (*api.RegisterOtpResp, error) {
	if req.Email == "" || req.FirstName == "" || req.LastName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing mandatory parametes")
	}

	if !utils.IsValidEmail(req.Email) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid email address: %s", req.Email)
	}

	count, err := s.validator.Count(ctx, nil)
	if err != nil {
		log.Printf("failed to fetch active email validation entry count: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if count > 10 {
		// TODO(prabhjot) just a mechanism right now to safe gaurd smtp connection
		// needs to be handled better and more granular
		return nil, status.Errorf(codes.ResourceExhausted, "Server Busy, Please try again later")
	}
	// Generate a random number between 0 and 999999
	otp := rand.Intn(1000000)

	entry := &table.EmailVerificationEntry{
		Key: &table.Email{
			Id: req.Email,
		},
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Otp:       fmt.Sprintf("%06d", otp),
		Created:   time.Now().Unix(),
	}

	// TODO(prabhjot) We probably need to consider sending emails from a controller rather than inline in the API
	content := fmt.Sprintf("Hi %s %s\n\tWelcome to the registration process, please use following OTP to validate your email\n\t\t%06d", req.FirstName, req.LastName, otp)
	m := &smtp.Message{
		Receivers: []string{req.Email},
		Subject:   "One Time Password for Registration Process",
		Body:      content,
	}

	err = s.sendMessage(m)
	if err != nil {
		log.Printf("failed to send OTP on the email provided: %s", err)
		if errors.IsInvalidArgument(err) {
			return nil, status.Errorf(codes.Unavailable, "Service not available")
		}
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	err = s.validator.Insert(ctx, entry.Key, entry)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.AlreadyExists, "Please wait, before trying to reattempt sending the code again")
		}
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.RegisterOtpResp{}, nil
}

func NewRegistrationServer(ctx *model.GrpcServerContext, ep string) *RegistrationServer {
	validator, err := table.GetEmailVerificationTable()
	if err != nil {
		log.Panicf("failed to get email verification table: %s", err)
	}
	srv := &RegistrationServer{
		validator: validator,
	}
	api.RegisterRegistrationServer(ctx.Server, srv)
	err = api.RegisterRegistrationHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesRegistration {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			IsPublic: utils.BoolP(true),
		}
		if err := routeTbl.Locate(context.Background(), entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	srv.initSmtpClient()
	return srv
}
